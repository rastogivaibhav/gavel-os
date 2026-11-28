//go:build linux

package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestApprovedRestartPayload(t *testing.T) {
	if os.Getenv("GAVEL_RESTART_PROBE") != "1" { t.Skip("guarded restart probe") }
	if os.Geteuid() != 421346 { t.Fatal("unexpected payload UID") }
	if os.Getenv("GAVEL_MACHINE_KEY") != "" { t.Fatal("machine key leaked") }
	for _, entry := range []struct{ env string; deny bool }{
		{"GAVEL_RESTART_ALLOW",false}, {"GAVEL_RESTART_DENY",true},
	} {
		conn,err:=net.DialTimeout("tcp4",os.Getenv(entry.env),time.Second)
		if conn!=nil {conn.Close()}
		if entry.deny {
			if err==nil || (!strings.Contains(err.Error(),"operation not permitted")&&!strings.Contains(err.Error(),"permission denied")){t.Fatalf("kernel deny: %v",err)}
		} else if err!=nil {t.Fatal(err)}
	}
	name,err:=guardedCgroupNameForPID(os.Getpid());if err!=nil{t.Fatal(err)}
	if err:=os.WriteFile(os.Getenv("GAVEL_RESTART_MARKER"),[]byte(name),0600);err!=nil{t.Fatal(err)}
}

func TestKernelGuardedApprovedRestart(t *testing.T) {
	if os.Getenv("GAVEL_RUN_KERNEL_TESTS")!="1"{t.Skip("requires isolated privileged VM")}
	if os.Geteuid()!=0{t.Fatal("requires root")}
	dir,err:=os.MkdirTemp("/tmp","gavel-restart-");if err!=nil{t.Fatal(err)};defer os.RemoveAll(dir)
	if err:=os.Chown(dir,421346,421346);err!=nil{t.Fatal(err)}
	marker:=filepath.Join(dir,"ran")
	oldListener,err:=net.ListenTCP("tcp4",&net.TCPAddr{IP:net.ParseIP("127.0.0.2")});if err!=nil{t.Fatal(err)};defer oldListener.Close()
	newListener,err:=net.ListenTCP("tcp4",&net.TCPAddr{IP:net.ParseIP("127.0.0.3")});if err!=nil{t.Fatal(err)};defer newListener.Close()
	var mode atomic.Int32
	var calls atomic.Int32
	server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		n:=calls.Add(1)
		state:=mode.Load()
		if state==2{w.WriteHeader(503);return}
		ip:="127.0.0.2"
		if state==1 || (state==3&&n>=3){ip="127.0.0.3"}
		_ = json.NewEncoder(w).Encode(RuntimePolicyResponse{ControlPlaneStatus:"online",BlockedIPv4:[]string{ip}})
	}))
	defer server.Close()
	t.Setenv("GAVEL_MACHINE_KEY","synthetic-restart")
	t.Setenv("GAVEL_ENGINE_URL",server.URL)
	t.Setenv("GAVEL_AGENT_UID","421346")
	t.Setenv("GAVEL_AGENT_GID","421346")
	t.Setenv("GAVEL_RESTART_MARKER",marker)
	t.Setenv("GAVEL_RESTART_PROBE","1")
	t.Setenv("GAVEL_RESTART_ALLOW",newListener.Addr().String())
	t.Setenv("GAVEL_RESTART_DENY",oldListener.Addr().String())
	exe,err:=os.Executable();if err!=nil{t.Fatal(err)}
	argv:=[]string{exe,"-test.run=^TestApprovedRestartPayload$","-test.v"}
	digest:=func(ip string)string{
		t.Helper()
		key,err:=parseIPv4(ip);if err!=nil{t.Fatal(err)}
		filter,err:=guardedSeccompFile(false);if err!=nil{t.Fatal(err)};defer filter.Close()
		d,err:=guardedPolicyDigest(LinuxEnforcerConfig{ProtectAll:true,BlockedIPv4:[]uint32{key}},421346,421346,"control_plane",nil,filter)
		if err!=nil{t.Fatal(err)};return d
	}
	oldDigest,newDigest:=digest("127.0.0.2"),digest("127.0.0.3")
	if err:=runGuardedAgent(argv);err!=nil{t.Fatal(err)}
	raw,err:=os.ReadFile(marker);if err!=nil{t.Fatal(err)}
	previous:=string(raw)
	if !guardedCgroupName.MatchString(previous){t.Fatal("invalid predecessor")}
	if err:=os.Remove(marker);err!=nil{t.Fatal(err)}
	parent,ok:=resolveLinuxCgroupPath();if !ok{t.Fatal("missing cgroup parent")}
	absent:=func(){t.Helper();if _,err:=os.Stat(marker);!os.IsNotExist(err){t.Fatalf("unexpected payload execution: %v",err)}}
	refuse:=func(approval,reason string){
		t.Helper()
		err:=restartGuardedAgent(previous,approval,argv)
		if err==nil||!strings.Contains(err.Error(),reason){t.Fatalf("expected %q refusal: %v",reason,err)}
		absent()
	}
	mode.Store(1)
	refuse("","explicit approved policy digest")
	refuse(oldDigest,"digest mismatch")
	mode.Store(2)
	refuse(newDigest,"policy unavailable")
	mode.Store(0);calls.Store(0);mode.Store(3)
	refuse(oldDigest,"pre-spawn remote authorization lost")
	mode.Store(1)
	// An unresolved predecessor (even empty) is not restart authorization.
	if err:=os.Mkdir(filepath.Join(parent,previous),0700);err!=nil{t.Fatal(err)}
	refuse(newDigest,"predecessor cleanup incomplete")
	if err:=os.Remove(filepath.Join(parent,previous));err!=nil{t.Fatal(err)}
	lease,err:=acquireGuardedLifecycleLease(previous);if err!=nil{t.Fatal(err)}
	refuse(newDigest,"predecessor lifecycle lease")
	if err:=lease.Close();err!=nil{t.Fatal(err)}
	t.Setenv("GAVEL_RESTART_ALLOW",oldListener.Addr().String())
	t.Setenv("GAVEL_RESTART_DENY",newListener.Addr().String())
	if err:=restartGuardedAgent(previous,newDigest,argv);err!=nil{t.Fatal(err)}
	raw,err=os.ReadFile(marker);if err!=nil{t.Fatal(err)}
	if string(raw)==previous||!guardedCgroupName.MatchString(string(raw)){t.Fatalf("not a fresh cgroup: %q",raw)}
	for _,name:=range []string{previous,string(raw)}{
		if _,err:=os.Stat(filepath.Join(parent,name));!os.IsNotExist(err){t.Fatalf("residual cgroup: %v",err)}
		base,err:=guardedPinPath(name);if err!=nil{t.Fatal(err)}
		for _,suffix:=range guardedNetworkPinSuffixes{if _,err:=os.Stat(base+suffix);!os.IsNotExist(err){t.Fatalf("residual pin: %v",err)}}
	}
	t.Log("KERNEL PROOF: approved fresh remote restart enforced changed policy; stale, unavailable, raced and unresolved predecessor states refused")
}
