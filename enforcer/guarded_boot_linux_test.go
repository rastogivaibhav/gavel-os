//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKernelGuardedBootInitialization(t *testing.T) {
	if os.Getenv("GAVEL_RUN_KERNEL_TESTS") != "1" { t.Skip("requires isolated privileged VM") }
	if os.Geteuid()!=0 { t.Fatal("requires root") }
	parent:="/sys/fs/cgroup"
	t.Setenv("GAVEL_CGROUP_PATH",parent)
	t.Setenv("GAVEL_MACHINE_KEY","")
	t.Setenv("GAVEL_BLOCKED_IPS","127.0.0.2")
	t.Setenv("GAVEL_BLOCKED_IPV6","")
	t.Setenv("GAVEL_MONITORED_PIDS","")
	t.Setenv("GAVEL_PROXY_IPV4","")
	t.Setenv("GAVEL_PROXY_PORT","")
	t.Setenv("GAVEL_AGENT_UID","421343")
	t.Setenv("GAVEL_AGENT_GID","421343")
	t.Setenv(guardedBootRequiredEnv,"1")
	if err:=guardedBootRoot();err!=nil{t.Fatal(err)}
	ready:=filepath.Join(guardedLifecycleRoot,guardedBootMarker)
	_ = os.Remove(ready)
	defer os.Remove(ready)
	dir,err:=os.MkdirTemp("/tmp","gavel-boot-");if err!=nil{t.Fatal(err)};defer os.RemoveAll(dir)
	if err:=os.Chown(dir,421343,421343);err!=nil{t.Fatal(err)}
	marker:=filepath.Join(dir,"ran")
	t.Setenv("GAVEL_ADMISSION_MARKER",marker)
	t.Setenv("GAVEL_ADMISSION_PROBE","1")
	exe,err:=os.Executable();if err!=nil{t.Fatal(err)}
	argv:=[]string{exe,"-test.run=^TestStrictAdmissionPayload$","-test.v"}
	refuse:=func(reason string){
		t.Helper()
		err:=runGuardedAgent(argv)
		if err==nil||!strings.Contains(err.Error(),reason){t.Fatalf("expected %q refusal: %v",reason,err)}
		if _,err:=os.Stat(marker);!os.IsNotExist(err){t.Fatalf("payload marker: %v",err)}
	}
	refuse("boot readiness unavailable")
	id,err:=currentGuardedBootIdentity(parent);if err!=nil{t.Fatal(err)}
	stale:=id;stale.BootID="00000000-0000-0000-0000-000000000000"
	if err:=writeGuardedBootMarker(stale);err!=nil{t.Fatal(err)}
	refuse("boot readiness identity mismatch")
	wrong:=id;wrong.Inode++
	if err:=writeGuardedBootMarker(wrong);err!=nil{t.Fatal(err)}
	refuse("boot readiness identity mismatch")
	// Exclusive boot initialization prevents even unmanaged guarded launches
	// while startup recovery is in progress.
	exclusive,err:=acquireGuardedBootLease(true);if err!=nil{t.Fatal(err)}
	refuse("boot lifecycle")
	if err:=exclusive.Close();err!=nil{t.Fatal(err)}
	shared,err:=acquireGuardedBootLease(false);if err!=nil{t.Fatal(err)}
	if err:=initializeGuardedBoot();err==nil||!strings.Contains(err.Error(),"boot lifecycle lease"){t.Fatalf("initialization while launch active: %v",err)}
	if err:=shared.Close();err!=nil{t.Fatal(err)}
	foreign,err:=os.MkdirTemp(parent,"gavel-agent-");if err!=nil{t.Fatal(err)};defer os.Remove(foreign)
	if err:=initializeGuardedBoot();err==nil||!strings.Contains(err.Error(),"unresolved guarded cgroup"){t.Fatalf("ambiguous cgroup must block initialization: %v",err)}
	if _,err:=os.Stat(foreign);err!=nil{t.Fatalf("unattributed cgroup changed: %v",err)}
	refuse("boot readiness unavailable")
	if err:=os.Remove(foreign);err!=nil{t.Fatal(err)}
	orphan,err:=os.MkdirTemp(parent,"gavel-agent-");if err!=nil{t.Fatal(err)}
	name:=filepath.Base(orphan)
	defer func(){if _,err:=os.Stat(orphan);err==nil{_ = unpinGuardedEnforcer(name);_ = os.Remove(orphan)}}()
	ip,err:=parseIPv4("127.0.0.2");if err!=nil{t.Fatal(err)}
	if _,err:=attachPinnedGuardedEnforcer(orphan,LinuxEnforcerConfig{ProtectAll:true,BlockedIPv4:[]uint32{ip}});err!=nil{t.Fatal(err)}
	if err:=initializeGuardedBoot();err!=nil{t.Fatal(err)}
	if _,err:=os.Stat(orphan);!os.IsNotExist(err){t.Fatalf("orphan remains: %v",err)}
	base,err:=guardedPinPath(name);if err!=nil{t.Fatal(err)}
	for _,suffix:=range guardedNetworkPinSuffixes{if _,err:=os.Stat(base+suffix);!os.IsNotExist(err){t.Fatalf("pin remains: %v",err)}}
	if err:=requireGuardedBootReady(parent);err!=nil{t.Fatal(err)}
	if err:=runGuardedAgent(argv);err!=nil{t.Fatal(err)}
	if got,err:=os.ReadFile(marker);err!=nil||string(got)!="ran"{t.Fatalf("positive payload: %q %v",got,err)}
	t.Log("KERNEL PROOF: boot gate rejected missing/stale/wrong-parent readiness and concurrent initialization; preserved unknown cgroup, recovered attributed orphan and admitted fresh guarded workload")
}
