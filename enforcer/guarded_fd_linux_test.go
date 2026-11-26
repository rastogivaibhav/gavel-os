//go:build linux

package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestGuardedOutputRejectsAmbientResources(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "output")
	if err != nil { t.Fatal(err) }; defer f.Close()
	if err := validateGuardedOutput(f); err == nil { t.Fatal("regular file accepted") }
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil { t.Fatal(err) }
	s := os.NewFile(uintptr(pair[0]),"socket")
	defer s.Close(); defer unix.Close(pair[1])
	if err := validateGuardedOutput(s); err == nil { t.Fatal("socket accepted") }
	rd, wr, err := os.Pipe()
	if err != nil { t.Fatal(err) }; defer rd.Close(); defer wr.Close()
	if err := validateGuardedOutput(rd); err == nil { t.Fatal("read endpoint accepted") }
	if err := validateGuardedOutput(wr); err != nil { t.Fatal(err) }
}

func TestGuardedDescriptorProbe(t *testing.T) {
	mode := os.Getenv("GAVEL_FD_TEST_MODE")
	if mode == "" { t.Skip("isolated descriptor probe") }
	if mode == "supervisor" {
		exe, err := os.Executable(); if err != nil { t.Fatal(err) }
		t.Setenv("GAVEL_FD_TEST_MODE","guarded")
		if err := runGuardedAgent([]string{exe,"-test.run=^TestGuardedDescriptorProbe$","-test.v"}); err != nil { t.Fatal(err) }
		return
	}
	if mode == "control" {
		for _, fd := range []int{3,4} {
			data := make([]byte, 1)
			n, err := unix.Read(fd,data)
			if err != nil || n != 1 || data[0] != 'X' { t.Fatalf("positive control fd %d: %v %v",fd,data,err) }
		}
		return
	}
	check := func() {
		t.Helper()
		buf := make([]byte, 1)
		if n, err := os.Stdin.Read(buf); n != 0 || err != io.EOF { t.Fatalf("stdin inherited: n=%d err=%v",n,err) }
		entries,err := os.ReadDir("/proc/self/fd"); if err != nil { t.Fatal(err) }
		for _, entry := range entries {
			target,err := os.Readlink(filepath.Join("/proc/self/fd",entry.Name()))
			if err != nil { continue } // directory FD may close after ReadDir
			if target == os.Getenv("GAVEL_FD_FILE") || target == os.Getenv("GAVEL_FD_SOCKET") {
				t.Fatalf("ambient resource leaked at fd %s",entry.Name())
			}
		}
		if err := validateGuardedOutput(os.Stdout); err != nil { t.Fatal(err) }
		if err := validateGuardedOutput(os.Stderr); err != nil { t.Fatal(err) }
	}
	check()
	if mode == "guarded" {
		exe, err := os.Executable(); if err != nil { t.Fatal(err) }
		cmd := exec.Command(exe,"-test.run=^TestGuardedDescriptorProbe$","-test.v")
		cmd.Env = append(os.Environ(),"GAVEL_FD_TEST_MODE=descendant")
		cmd.Stdin,cmd.Stdout,cmd.Stderr=os.Stdin,os.Stdout,os.Stderr
		if err := cmd.Run(); err != nil { t.Fatal(err) }
	}
	t.Log("KERNEL PROOF: ambient file/socket not inherited; stdin EOF; output endpoints safe")
}

func TestKernelGuardedDescriptors(t *testing.T) {
	if os.Getenv("GAVEL_RUN_KERNEL_TESTS") != "1" { t.Skip("requires isolated privileged VM") }
	if os.Geteuid()!=0 { t.Fatal("requires root") }
	secret,err := os.CreateTemp("/tmp","gavel-fd-fixture-")
	if err != nil { t.Fatal(err) }; defer os.Remove(secret.Name()); defer secret.Close()
	if _,err:=secret.Write([]byte("XX"));err!=nil {t.Fatal(err)}
	if _,err:=secret.Seek(0,0);err!=nil {t.Fatal(err)}
	pair,err := unix.Socketpair(unix.AF_UNIX,unix.SOCK_STREAM|unix.SOCK_CLOEXEC,0)
	if err != nil { t.Fatal(err) }
	sock:=os.NewFile(uintptr(pair[0]),"fixture-socket")
	defer sock.Close(); defer unix.Close(pair[1])
	if _,err:=unix.Write(pair[1],[]byte("XX"));err!=nil {t.Fatal(err)}
	socketName,err:=os.Readlink(fmt.Sprintf("/proc/self/fd/%d",sock.Fd()))
	if err!=nil {t.Fatal(err)}
	exe,err:=os.Executable(); if err!=nil {t.Fatal(err)}
	t.Setenv("GAVEL_FD_FILE",secret.Name())
	t.Setenv("GAVEL_FD_SOCKET",socketName)
	control:=exec.Command(exe,"-test.run=^TestGuardedDescriptorProbe$","-test.v")
	control.Env=append(os.Environ(),"GAVEL_FD_TEST_MODE=control")
	control.ExtraFiles=[]*os.File{secret,sock}
	control.SysProcAttr=&syscall.SysProcAttr{Credential:&syscall.Credential{Uid:65534,Gid:65534}}
	if out,err:=control.CombinedOutput();err!=nil || !strings.Contains(string(out),"PASS: TestGuardedDescriptorProbe") {t.Fatalf("unguarded control: %v %s",err,out)}
	t.Setenv("GAVEL_MACHINE_KEY","")
	t.Setenv("GAVEL_MONITORED_PIDS","")
	t.Setenv("GAVEL_BLOCKED_IPS","127.0.0.2")
	t.Setenv("GAVEL_AGENT_UID","65534")
	t.Setenv("GAVEL_AGENT_GID","65534")
	supervisor:=exec.Command(exe,"-test.run=^TestGuardedDescriptorProbe$","-test.v")
	supervisor.Env=append(os.Environ(),"GAVEL_FD_TEST_MODE=supervisor")
	supervisor.ExtraFiles=[]*os.File{secret,sock,secret}
	supervisor.Stdin=secret
	// CombinedOutput supplies write-only pipes rather than arbitrary host FDs.
	out,err:=supervisor.CombinedOutput()
	if err!=nil || !strings.Contains(string(out),"KERNEL PROOF: ambient file/socket not inherited") {t.Fatalf("guarded probe: %v %s",err,out)}
	if offset,err:=secret.Seek(0,io.SeekCurrent);err!=nil || offset!=1 {t.Fatalf("fixture read unexpectedly: offset=%d err=%v",offset,err)}
	if err:=unix.SetNonblock(pair[0],true);err!=nil {t.Fatal(err)}
	buf:=make([]byte,1)
	if n,err:=unix.Read(pair[0],buf);err!=nil || n!=1 || buf[0]!='X' {t.Fatalf("fixture socket drained: %d %v",n,err)}
}
