//go:build linux

package main

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func checkPrivateIPC(t *testing.T) {
	t.Helper()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil { t.Fatalf("approved private stream pair: %v", err) }
	defer unix.Close(pair[0])
	defer unix.Close(pair[1])
	if n, err := unix.Write(pair[0], []byte("local")); err != nil || n != 5 {
		t.Fatalf("private write: %d %v", n, err)
	}
	var buf [5]byte
	if n, err := unix.Read(pair[1], buf[:]); err != nil || n != 5 || string(buf[:]) != "local" {
		t.Fatalf("private read: %d %q %v", n, buf, err)
	}
	for _, kind := range []int{unix.SOCK_DGRAM, unix.SOCK_SEQPACKET} {
		fds, err := unix.Socketpair(unix.AF_UNIX, kind|unix.SOCK_CLOEXEC, 0)
		if err == nil {
			unix.Close(fds[0]); unix.Close(fds[1])
		}
		if !errors.Is(err, unix.EPERM) { t.Fatalf("unapproved socketpair type %d: %v", kind, err) }
	}
}

func TestGuardedUnixIPCProbe(t *testing.T) {
	mode := os.Getenv("GAVEL_IPC_TEST_MODE")
	if mode == "" { t.Skip("isolated Unix IPC probe") }
	for _, path := range []string{os.Getenv("GAVEL_IPC_PATH"), os.Getenv("GAVEL_IPC_ABSTRACT")} {
		conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name:path, Net:"unix"})
		if mode == "control" {
			if err != nil { t.Fatal(err) }
			defer conn.Close()
			if err := conn.SetReadDeadline(time.Now().Add(3*time.Second)); err != nil { t.Fatal(err) }
			payload, ancillary := make([]byte, 8), make([]byte, unix.CmsgSpace(4))
			n, oobn, _, _, err := conn.ReadMsgUnix(payload, ancillary)
			if err != nil || n != 1 || payload[0] != 'X' { t.Fatalf("fixture transfer: %d %v", n, err) }
			msgs, err := unix.ParseSocketControlMessage(ancillary[:oobn])
			if err != nil || len(msgs) != 1 { t.Fatalf("fixture control message: %v",err) }
			fds, err := unix.ParseUnixRights(&msgs[0])
			if err != nil || len(fds) != 1 { t.Fatalf("fixture descriptor: %v",err) }
			var b [1]byte
			got, err := unix.Read(fds[0], b[:])
			unix.Close(fds[0])
			if err != nil || got != 1 || b[0] != 'S' { t.Fatalf("positive fixture read: %d %q %v",got,b,err) }
		} else {
			if conn != nil { conn.Close() }
			if !errors.Is(err, unix.EPERM) { t.Fatalf("external UNIX connection must fail with EPERM: %v",err) }
		}
	}
	if mode == "control" { return }
	checkPrivateIPC(t)
	if mode == "guarded" {
		exe, err := os.Executable()
		if err != nil { t.Fatal(err) }
		cmd := exec.Command(exe,"-test.run=^TestGuardedUnixIPCProbe$","-test.v")
		cmd.Env = append(os.Environ(),"GAVEL_IPC_TEST_MODE=descendant")
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil { t.Fatalf("descendant IPC proof: %v",err) }
	}
	t.Log("KERNEL PROOF: external pathname/abstract Unix services denied; private stream pair usable")
}

func TestKernelGuardedUnixIPC(t *testing.T) {
	if os.Getenv("GAVEL_RUN_KERNEL_TESTS") != "1" { t.Skip("requires isolated privileged VM") }
	if os.Geteuid() != 0 { t.Fatal("requires root") }
	dir, err := os.MkdirTemp("/tmp","gavel-ipc-")
	if err != nil { t.Fatal(err) }
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir,0755); err != nil { t.Fatal(err) }
	path := filepath.Join(dir,"service.sock")
	abstract := "@"+filepath.Base(dir)
	listeners := make([]*net.UnixListener,0,2)
	for _, name := range []string{path,abstract} {
		l, err := net.ListenUnix("unix",&net.UnixAddr{Name:name,Net:"unix"})
		if err != nil { t.Fatal(err) }
		defer l.Close()
		listeners=append(listeners,l)
	}
	if err := os.Chmod(path,0666); err != nil { t.Fatal(err) }
	fixture := filepath.Join(dir,"synthetic")
	if err := os.WriteFile(fixture,[]byte("S"),0600); err != nil { t.Fatal(err) }
	results := make(chan error,2)
	for _, l := range listeners {
		go func(l *net.UnixListener) {
			if err:=l.SetDeadline(time.Now().Add(5*time.Second));err!=nil { results<-err;return }
			c,err:=l.AcceptUnix()
			if err!=nil { results<-err;return }
			defer c.Close()
			f,err:=os.Open(fixture)
			if err!=nil { results<-err;return }
			defer f.Close()
			_,_,err=c.WriteMsgUnix([]byte("X"),unix.UnixRights(int(f.Fd())),nil)
			results<-err
		}(l)
	}
	t.Setenv("GAVEL_IPC_PATH",path)
	t.Setenv("GAVEL_IPC_ABSTRACT",abstract)
	exe,err:=os.Executable()
	if err!=nil { t.Fatal(err) }
	control:=exec.Command(exe,"-test.run=^TestGuardedUnixIPCProbe$","-test.v")
	control.Env=append(os.Environ(),"GAVEL_IPC_TEST_MODE=control")
	control.SysProcAttr=&syscall.SysProcAttr{Credential:&syscall.Credential{Uid:65534,Gid:65534}}
	if out,err:=control.CombinedOutput();err!=nil || !strings.Contains(string(out),"PASS: TestGuardedUnixIPCProbe") {
		t.Fatalf("unguarded positive control: %v %s",err,out)
	}
	for range listeners { if err:=<-results;err!=nil { t.Fatal(err) } }
	t.Setenv("GAVEL_MACHINE_KEY","")
	t.Setenv("GAVEL_MONITORED_PIDS","")
	t.Setenv("GAVEL_BLOCKED_IPS","127.0.0.2")
	t.Setenv("GAVEL_AGENT_UID","65534")
	t.Setenv("GAVEL_AGENT_GID","65534")
	t.Setenv("GAVEL_IPC_TEST_MODE","guarded")
	if err:=runGuardedAgent([]string{exe,"-test.run=^TestGuardedUnixIPCProbe$","-test.v"});err!=nil { t.Fatal(err) }
	for _,l:=range listeners {
		if err:=l.SetDeadline(time.Now().Add(100*time.Millisecond));err!=nil { t.Fatal(err) }
		c,err:=l.AcceptUnix()
		if c!=nil { c.Close();t.Fatal("forbidden service received connection") }
		var ne net.Error
		if !errors.As(err,&ne) || !ne.Timeout() { t.Fatalf("negative server observation: %v",err) }
	}
}
