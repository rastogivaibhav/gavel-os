//go:build linux

package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"sync/atomic"

	"github.com/cilium/ebpf/link"
)

func TestActivePolicyPayload(t *testing.T) {
	mode := os.Getenv("GAVEL_WATCHDOG_TEST_PAYLOAD")
	if mode == "" { t.Skip("guarded watchdog fixture only") }
	if os.Geteuid() != 421345 { t.Fatal("unexpected payload UID") }
	if os.Getenv("GAVEL_MACHINE_KEY") != "" { t.Fatal("machine key leaked") }
	dir := os.Getenv("GAVEL_WATCHDOG_TEST_DIR")
	if mode == "parent" {
		exe, err := os.Executable()
		if err != nil { t.Fatal(err) }
		child := exec.Command(exe, "-test.run=^TestActivePolicyPayload$", "-test.v")
		child.Env = append(os.Environ(), "GAVEL_WATCHDOG_TEST_PAYLOAD=descendant")
		if err := child.Start(); err != nil { t.Fatal(err) }
		_ = child.Wait()
		return
	}
	// Positive control and actual denied syscall, before the outage.
	allowed, err := net.DialTimeout("tcp4", os.Getenv("GAVEL_WATCHDOG_TEST_ALLOW"), time.Second)
	if err != nil { t.Fatal(err) }
	allowed.Close()
	denied, err := net.DialTimeout("tcp4", os.Getenv("GAVEL_WATCHDOG_TEST_DENY"), time.Second)
	if denied != nil { denied.Close() }
	if err == nil || (!strings.Contains(err.Error(), "operation not permitted") && !strings.Contains(err.Error(), "permission denied")) {
		t.Fatalf("expected kernel refusal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir,"ready"), []byte(strconv.Itoa(os.Getpid())),0600); err != nil { t.Fatal(err) }
	for { time.Sleep(100*time.Millisecond) }
}

func TestKernelGuardedActivePolicyWatchdog(t *testing.T) {
	if os.Getenv("GAVEL_RUN_KERNEL_TESTS") != "1" { t.Skip("requires isolated privileged VM") }
	if os.Geteuid() != 0 { t.Fatal("requires root") }
	for _, mode := range []string{"outage", "changed", "revoked", "degraded"} {
		t.Run(mode,func(t *testing.T){
			dir, err := os.MkdirTemp("/tmp","gavel-watchdog-")
			if err != nil { t.Fatal(err) }; defer os.RemoveAll(dir)
			if err := os.Chown(dir,421345,421345); err != nil { t.Fatal(err) }
			allowed, err := net.ListenTCP("tcp4",&net.TCPAddr{IP:net.ParseIP("127.0.0.1")})
			if err != nil { t.Fatal(err) }; defer allowed.Close()
			denied, err := net.ListenTCP("tcp4",&net.TCPAddr{IP:net.ParseIP("127.0.0.2")})
			if err != nil { t.Fatal(err) }; defer denied.Close()
			var failed atomic.Bool
			var polls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
				polls.Add(1)
				p := RuntimePolicyResponse{ControlPlaneStatus:"online", BlockedIPv4:[]string{"127.0.0.2"}}
				if failed.Load() {
					switch mode {
					case "outage": w.WriteHeader(503); return
					case "changed": p.BlockedIPv4=[]string{"127.0.0.3"}
					case "revoked": p.BlockedIPv4=nil
					case "degraded": p.ControlPlaneStatus="degraded"
					}
				}
				_ = json.NewEncoder(w).Encode(p)
			}))
			defer server.Close()
			t.Setenv("GAVEL_ENGINE_URL",server.URL)
			t.Setenv("GAVEL_MACHINE_KEY","synthetic-watchdog-fixture")
			t.Setenv("GAVEL_AGENT_UID","421345")
			t.Setenv("GAVEL_AGENT_GID","421345")
			t.Setenv("GAVEL_WATCHDOG_TEST_DIR",dir)
			t.Setenv("GAVEL_WATCHDOG_TEST_ALLOW",allowed.Addr().String())
			t.Setenv("GAVEL_WATCHDOG_TEST_DENY",denied.Addr().String())
			t.Setenv("GAVEL_WATCHDOG_TEST_PAYLOAD","parent")
			exe,err:=os.Executable(); if err!=nil {t.Fatal(err)}
			result:=make(chan error,1)
			go func(){result<-runGuardedAgent([]string{exe,"-test.run=^TestActivePolicyPayload$","-test.v"})}()
			// Do not mutate environment or remove fixtures until supervisor returns.
			defer func(){ failed.Store(true); if result!=nil { <-result } }()
			raw,err:=waitForProofFile(filepath.Join(dir,"ready"),10*time.Second)
			if err!=nil { t.Fatal(err) }
			pid,err:=strconv.Atoi(string(raw));if err!=nil {t.Fatal(err)}
			name,err:=guardedCgroupNameForPID(pid);if err!=nil {t.Fatal(err)}
			base,err:=guardedPinPath(name);if err!=nil {t.Fatal(err)}
			for _,suffix:=range guardedNetworkPinSuffixes {
				l,err:=link.LoadPinnedLink(base+suffix,nil);if err!=nil {t.Fatal(err)};l.Close()
			}
			// Require an unchanged healthy refresh before changing the server.
			initial:=polls.Load()
			deadline:=time.Now().Add(8*time.Second)
			for polls.Load()<=initial && time.Now().Before(deadline) {time.Sleep(25*time.Millisecond)}
			if polls.Load()<=initial {t.Fatal("no healthy policy refresh")}
			if err:=syscallKillZero(pid);err!=nil {t.Fatal(err)}
			failed.Store(true)
			select {
			case err:=<-result:
				result=nil
				if err==nil||!strings.Contains(err.Error(),"active guarded policy authorization lost"){t.Fatalf("unexpected result: %v",err)}
			case <-time.After(13*time.Second): t.Fatal("watchdog failed to terminate workload within test window")
			}
			parent,ok:=resolveLinuxCgroupPath();if !ok {t.Fatal("missing cgroup parent")}
			if _,err:=os.Stat(filepath.Join(parent,name));!os.IsNotExist(err){t.Fatalf("cgroup remains: %v",err)}
			for _,suffix:=range guardedNetworkPinSuffixes {
				if _,err:=os.Stat(base+suffix);!os.IsNotExist(err){t.Fatalf("pin remains: %v",err)}
			}
			if err:=allowed.SetDeadline(time.Now().Add(time.Second));err!=nil {t.Fatal(err)}
			c,err:=allowed.AcceptTCP();if err!=nil {t.Fatal(err)};c.Close()
			if err:=denied.SetDeadline(time.Now().Add(100*time.Millisecond));err!=nil {t.Fatal(err)}
			c,err=denied.AcceptTCP();if c!=nil {c.Close();t.Fatal("denied receiver observed traffic")}
			ne,ok:=err.(net.Error);if !ok||!ne.Timeout(){t.Fatalf("negative receiver: %v",err)}
			t.Logf("KERNEL PROOF: active %s terminated guarded parent and descendant before pin cleanup; unchanged refresh and receiver controls passed",mode)
		})
	}
}
