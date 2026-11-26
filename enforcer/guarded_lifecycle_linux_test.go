//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

func TestGuardedLifecycleRejectInvalidName(t *testing.T){
	for _,name:=range []string{"","../gavel-agent-1","gavel-agent-1/extra","other","gavel-agent-foo"}{
		if f,err:=acquireGuardedLifecycleLease(name);err==nil{f.Close();t.Fatalf("invalid name accepted: %q",name)}
	}
}

func TestKernelGuardedLifecycleLease(t *testing.T){
	if os.Getenv("GAVEL_RUN_KERNEL_TESTS")!="1"{t.Skip("requires isolated privileged VM")}
	if os.Geteuid()!=0{t.Fatal("requires root")}
	name:="gavel-agent-"+strconv.Itoa(os.Getpid())+"941"
	lease,err:=acquireGuardedLifecycleLease(name)
	if err!=nil{t.Fatal(err)}
	defer lease.Close()
	path:=filepath.Join(guardedLifecycleRoot,name+".lock")
	flags,err:=unix.FcntlInt(lease.Fd(),unix.F_GETFD,0)
	if err!=nil||flags&unix.FD_CLOEXEC==0{t.Fatalf("lease not close-on-exec: %v %v",flags,err)}
	if other,err:=acquireGuardedLifecycleLease(name);!errors.Is(err,unix.EWOULDBLOCK){
		if other!=nil{other.Close()}
		t.Fatalf("concurrent lease must be refused: %v",err)
	}
	if err:=lease.Close();err!=nil{t.Fatal(err)}
	again,err:=acquireGuardedLifecycleLease(name)
	if err!=nil{t.Fatalf("released lease unavailable: %v",err)}
	if err:=again.Close();err!=nil{t.Fatal(err)}
	if err:=os.Chmod(path,0666);err!=nil{t.Fatal(err)}
	defer os.Chmod(path,0600)
	if bad,err:=acquireGuardedLifecycleLease(name);err==nil{bad.Close();t.Fatal("writable lifecycle inode accepted")}
	t.Log("KERNEL PROOF: exclusive close-on-exec lifecycle lease, release and unsafe inode rejection")
}
