//go:build linux

package main

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCredentialUIDMatches(t *testing.T){
	for _,c:=range []struct{status string; match,valid bool}{
		{"Uid:\t0\t0\t0\t0\n",false,true},
		{"Uid:\t42\t0\t0\t0\n",true,true},
		{"Uid:\t0\t42\t0\t0\n",true,true},
		{"Uid:\t0\t0\t42\t0\n",true,true},
		{"Uid:\t0\t0\t0\t42\n",true,true},
		{"Uid:\t0\t0\t0\n",false,false},
		{"Uid:\t42\t0\t0\tx\n",false,false},
		{"Name:\ttest\n",false,false},
	}{
		got,err:=credentialUIDMatches(c.status,42)
		if (err==nil)!=c.valid||got!=c.match{t.Fatalf("record %q: %t %v",c.status,got,err)}
	}
}

func TestGuardedHelperIdentityProbe(t *testing.T){
	if os.Getenv("GAVEL_HELPER_IDENTITY_PROBE")!="1"{t.Skip("guarded helper identity probe")}
	if os.Getuid()!=421337||os.Geteuid()!=421337{t.Fatal("unexpected agent UID")}
	t.Log("KERNEL PROOF: guarded payload ran under dedicated unused UID")
}

func TestKernelGuardedHelperIdentity(t *testing.T){
	if os.Getenv("GAVEL_RUN_KERNEL_TESTS")!="1"{t.Skip("requires isolated privileged VM")}
	if os.Geteuid()!=0{t.Fatal("requires root")}
	const uid=421337
	// First positive control: acquire the unused numeric UID; a second
	// supervisor cannot simultaneously reserve the same identity.
	lease,err:=acquireGuardedUIDLease(uid)
	if err!=nil{t.Fatal(err)}
	if other,err:=acquireGuardedUIDLease(uid);err==nil{other.Close();lease.Close();t.Fatal("duplicate UID lease accepted")}
	if err:=lease.Close();err!=nil{t.Fatal(err)}
	// Synthetic same-UID process, harmless and restricted to this VM.
	helper:=exec.Command("/bin/sleep","30")
	helper.SysProcAttr=&syscall.SysProcAttr{Credential:&syscall.Credential{Uid:uid,Gid:uid}}
	if err:=helper.Start();err!=nil{t.Fatal(err)}
	defer func(){if helper.ProcessState==nil{helper.Process.Kill();helper.Wait()}}()
	if err:=requireUnusedGuardedUID(uid);err==nil{t.Fatal("active same-UID helper not detected")}
	t.Setenv("GAVEL_MACHINE_KEY","")
	t.Setenv("GAVEL_MONITORED_PIDS","")
	t.Setenv("GAVEL_BLOCKED_IPS","127.0.0.2")
	t.Setenv("GAVEL_AGENT_UID","421337")
	t.Setenv("GAVEL_AGENT_GID","421337")
	t.Setenv("GAVEL_HELPER_IDENTITY_PROBE","1")
	exe,err:=os.Executable();if err!=nil{t.Fatal(err)}
	argv:=[]string{exe,"-test.run=^TestGuardedHelperIdentityProbe$","-test.v"}
	if err:=runGuardedAgent(argv);err==nil||!strings.Contains(err.Error(),"already in use"){
		t.Fatalf("same-UID helper must prevent launch: %v",err)
	}
	if err:=helper.Process.Kill();err!=nil{t.Fatal(err)}
	_ = helper.Wait()
	deadline:=time.Now().Add(time.Second)
	for {
		if err:=requireUnusedGuardedUID(uid);err==nil{break}
		if time.Now().After(deadline){t.Fatal("UID did not become unused after helper exit")}
		time.Sleep(10*time.Millisecond)
	}
	if err:=runGuardedAgent(argv);err!=nil{t.Fatalf("unused UID positive control: %v",err)}
	t.Log("KERNEL PROOF: duplicate UID lease and live same-UID helper rejected before launch")
}
