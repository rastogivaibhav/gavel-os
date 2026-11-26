//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestIsolatedFilesystemProfileValidation(t *testing.T) {
	for _, path := range []string{"/", "/dev", "/dev/shm", "/dev/shm/fixture", "/dev/mqueue", "/proc", "/proc/self/status", "/sys", "/run", "/run/agent"} {
		if isolatedFilesystemPathAllowed(path) {
			t.Fatalf("accepted protected path %q", path)
		}
	}
	for _, path := range []string{"/usr/lib", "/tmp/private-work", "/dev/shm-other", "/proc-other"} {
		if !isolatedFilesystemPathAllowed(path) {
			t.Fatalf("rejected unrelated path %q", path)
		}
	}
	t.Setenv(guardedFilesystemProfileEnv, "isolated")
	t.Setenv(guardedFilesystemEnv, "")
	if err := os.Unsetenv(guardedFilesystemEnv); err != nil { t.Fatal(err) }
	if _, err := guardedFilesystemArguments(); err == nil || !strings.Contains(err.Error(), "requires") {
		t.Fatalf("missing mandatory policy: %v", err)
	}
	t.Setenv(guardedFilesystemProfileEnv, "unknown")
	if _, err := guardedFilesystemArguments(); err == nil { t.Fatal("unknown profile accepted") }
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink("/proc", alias); err != nil { t.Fatal(err) }
	for _, path := range []string{"/dev", "/proc", alias} {
		raw, err := json.Marshal(guardedFilesystemPolicy{Read: []string{path}, Execute: []string{"/bin/true"}})
		if err != nil { t.Fatal(err) }
		if _, err := compileGuardedFilesystemPolicyForProfile(string(raw), true); err == nil {
			t.Fatalf("isolated profile accepted %q", path)
		}
	}
	for _, v := range guardedWorkloadEnvironment([]string{guardedFilesystemProfileEnv+"=isolated", guardedFilesystemEnv+"=secret", "PATH=/bin"}) {
		if strings.HasPrefix(v, "GAVEL_AGENT_FS_") { t.Fatal("profile or policy leaked to payload") }
	}
}

func mapIPCFile(path, expect, update string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil { return err }
	defer f.Close()
	b, err := unix.Mmap(int(f.Fd()), 0, 4096, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil { return err }
	defer unix.Munmap(b)
	if string(b[:len(expect)]) != expect { return errors.New("unexpected fixture contents") }
	copy(b, update)
	return unix.Msync(b, unix.MS_SYNC)
}

func TestGuardedFileIPCProfileProbe(t *testing.T) {
	mode := os.Getenv("GAVEL_FILEIPC_MODE")
	if mode == "" { t.Skip("isolated file IPC probe") }
	shared := os.Getenv("GAVEL_FILEIPC_SHARED")
	fifo := os.Getenv("GAVEL_FILEIPC_FIFO")
	private := os.Getenv("GAVEL_FILEIPC_PRIVATE")
	fifoRoundtrip := func() error {
		fd, err := unix.Open(fifo, unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil { return err }
		defer unix.Close(fd)
		if n, err := unix.Write(fd, []byte("F")); err != nil || n != 1 { return errors.New("FIFO write failed") }
		var b [1]byte
		if n, err := unix.Read(fd, b[:]); err != nil || n != 1 || b[0] != 'F' { return errors.New("FIFO read failed") }
		return nil
	}
	if mode == "control" {
		if err := mapIPCFile(shared, "seed", "ctrl"); err != nil { t.Fatal(err) }
		if err := fifoRoundtrip(); err != nil { t.Fatal(err) }
		return
	}
	deny := func(op string, err error) {
		t.Helper()
		if !errors.Is(err, unix.EACCES) && !errors.Is(err, unix.EPERM) { t.Fatalf("%s expected kernel denial: %v", op, err) }
	}
	deny("external file-backed shared memory read/write mmap", mapIPCFile(shared, "ctrl", "bad!"))
	_, err := os.ReadFile(shared)
	deny("external shared memory read", err)
	fd, err := unix.Open(fifo, unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if fd >= 0 { unix.Close(fd) }
	deny("external FIFO open", err)
	if os.Getenv(guardedFilesystemProfileEnv) != "" || os.Getenv(guardedFilesystemEnv) != "" { t.Fatal("host profile leaked") }
	if err := mapIPCFile(private, "safe", "safe"); err != nil { t.Fatalf("private workspace mmap: %v", err) }
	if mode == "guarded" {
		exe := os.Getenv("GAVEL_FILEIPC_EXE")
		cmd := exec.Command(exe, "-test.run=^TestGuardedFileIPCProfileProbe$", "-test.v")
		cmd.Env = append(os.Environ(), "GAVEL_FILEIPC_MODE=descendant")
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil { t.Fatalf("descendant proof: %v", err) }
	}
	t.Log("KERNEL PROOF: external shared-memory file and FIFO denied; private mapped file allowed")
}

func TestKernelGuardedFileIPCProfile(t *testing.T) {
	if os.Getenv("GAVEL_RUN_KERNEL_TESTS") != "1" { t.Skip("requires isolated privileged VM") }
	if os.Geteuid() != 0 { t.Fatal("requires root") }
	shared, err := os.CreateTemp("/dev/shm", "gavel-fileipc-")
	if err != nil { t.Fatal(err) }
	defer os.Remove(shared.Name())
	defer shared.Close()
	if err := shared.Truncate(4096); err != nil { t.Fatal(err) }
	if _, err := shared.WriteAt([]byte("seed"), 0); err != nil { t.Fatal(err) }
	if err := shared.Chmod(0666); err != nil { t.Fatal(err) }
	root, err := os.MkdirTemp("/tmp", "gavel-fileipc-")
	if err != nil { t.Fatal(err) }
	defer os.RemoveAll(root)
	if err := os.Chmod(root, 0755); err != nil { t.Fatal(err) }
	fifo := filepath.Join(root, "external-fifo")
	if err := unix.Mkfifo(fifo, 0666); err != nil { t.Fatal(err) }
	if err := os.Chmod(fifo, 0666); err != nil { t.Fatal(err) }
	work := filepath.Join(root, "private")
	if err := os.Mkdir(work, 0700); err != nil { t.Fatal(err) }
	if err := os.Chown(work, 421339, 421339); err != nil { t.Fatal(err) }
	private := filepath.Join(work, "mapped")
	p, err := os.OpenFile(private, os.O_CREATE|os.O_RDWR|os.O_EXCL, 0600)
	if err != nil { t.Fatal(err) }
	if err := p.Truncate(4096); err != nil { p.Close(); t.Fatal(err) }
	if _, err := p.WriteAt([]byte("safe"), 0); err != nil { p.Close(); t.Fatal(err) }
	if err := p.Chown(421339, 421339); err != nil { p.Close(); t.Fatal(err) }
	if err := p.Close(); err != nil { t.Fatal(err) }
	exe, err := os.Executable()
	if err != nil { t.Fatal(err) }
	t.Setenv("GAVEL_FILEIPC_SHARED", shared.Name())
	t.Setenv("GAVEL_FILEIPC_FIFO", fifo)
	t.Setenv("GAVEL_FILEIPC_PRIVATE", private)
	t.Setenv("GAVEL_FILEIPC_EXE", exe)
	argv := []string{exe, "-test.run=^TestGuardedFileIPCProfileProbe$", "-test.v"}
	control := exec.Command(argv[0], argv[1:]...)
	control.Env = append(os.Environ(), "GAVEL_FILEIPC_MODE=control")
	control.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid:421339, Gid:421339}}
	if out, err := control.CombinedOutput(); err != nil || !strings.Contains(string(out), "PASS: TestGuardedFileIPCProfileProbe") {
		t.Fatalf("unguarded positive control: %v %s", err, out)
	}
	read := []string{work, exe}
	execute := []string{exe}
	for _, path := range []string{"/usr/lib", "/lib", "/lib64", "/etc/ld.so.cache"} {
		if _, err := os.Stat(path); err != nil { continue }
		read = append(read, path)
		if path != "/etc/ld.so.cache" { execute = append(execute, path) }
	}
	policy, err := json.Marshal(guardedFilesystemPolicy{Read:read, Write:[]string{work}, Execute:execute})
	if err != nil { t.Fatal(err) }
	t.Setenv(guardedFilesystemProfileEnv, "isolated")
	t.Setenv(guardedFilesystemEnv, string(policy))
	t.Setenv("GAVEL_MACHINE_KEY", "")
	t.Setenv("GAVEL_MONITORED_PIDS", "")
	t.Setenv("GAVEL_BLOCKED_IPS", "127.0.0.2")
	t.Setenv("GAVEL_AGENT_UID", "421339")
	t.Setenv("GAVEL_AGENT_GID", "421339")
	t.Setenv("GAVEL_FILEIPC_MODE", "guarded")
	if err := runGuardedAgent(argv); err != nil { t.Fatal(err) }
	var got [4]byte
	if _, err := shared.ReadAt(got[:], 0); err != nil || string(got[:]) != "ctrl" { t.Fatalf("external shared file changed: %q %v", got, err) }
	if info, err := os.Lstat(fifo); err != nil || info.Mode()&os.ModeNamedPipe == 0 { t.Fatalf("FIFO fixture removed: %v", err) }
	t.Log("KERNEL PROOF: external file-backed IPC fixture unchanged after guarded parent and descendant")
}
