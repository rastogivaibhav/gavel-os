//go:build linux

package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

// Classic BPF seccomp data offsets: nr=0, arch=4, args[0]=16,
// args[1]=24 on the supported little-endian 64-bit Linux ABIs.
const (
	scLoad = 0x20
	scEqual = 0x15
	scSet = 0x45
	scAnd = 0x54
	scReturn = 0x06
	scAllow = 0x7fff0000
	scKill = 0x80000000
	scErrno = 0x00050000
)

func guardedSeccompProgram(tcpOnly ...bool) ([]unix.SockFilter, error) {
	var arch uint32
	switch runtime.GOARCH {
	case "amd64":
		arch = 0xc000003e
	case "arm64":
		arch = 0xc00000b7
	default:
		return nil, fmt.Errorf("unsupported guarded seccomp ABI: %s", runtime.GOARCH)
	}
	ins := func(code uint16, k uint32, jt, jf uint8) unix.SockFilter {
		return unix.SockFilter{Code: code, K: k, Jt: jt, Jf: jf}
	}
	deny := uint32(scErrno) | uint32(unix.EPERM)
	p := []unix.SockFilter{
		ins(scLoad, 4, 0, 0), ins(scEqual, arch, 1, 0), ins(scReturn, scKill, 0, 0),
		ins(scLoad, 0, 0, 0),
	}
	if runtime.GOARCH == "amd64" {
		// Reject alternate x32 ABI rather than matching native syscall numbers.
		p = append(p, ins(scSet, 0x40000000, 0, 1), ins(scReturn, scKill, 0, 0))
	}
	// Explicitly blocked management operations. This is a scoped deny policy,
	// not an exhaustive syscall allowlist or a filesystem sandbox.
	for _, nr := range []uint32{
		unix.SYS_UNSHARE, unix.SYS_SETNS, unix.SYS_BPF, unix.SYS_PERF_EVENT_OPEN,
		unix.SYS_MOUNT, unix.SYS_UMOUNT2, unix.SYS_PIVOT_ROOT,
		unix.SYS_OPEN_TREE, unix.SYS_MOVE_MOUNT, unix.SYS_FSOPEN,
		unix.SYS_FSCONFIG, unix.SYS_FSMOUNT, unix.SYS_FSPICK, unix.SYS_MOUNT_SETATTR,
		unix.SYS_INIT_MODULE, unix.SYS_FINIT_MODULE, unix.SYS_DELETE_MODULE,
		unix.SYS_KEXEC_LOAD, unix.SYS_REBOOT, unix.SYS_SWAPON, unix.SYS_SWAPOFF,
		unix.SYS_PTRACE, unix.SYS_PROCESS_VM_WRITEV, unix.SYS_IO_URING_SETUP,
		unix.SYS_PIDFD_GETFD, unix.SYS_PROCESS_VM_READV,
		// Shared host IPC objects are not authorized by the agent's network
		// or filesystem policy. Deny System V IPC and POSIX message queues.
		unix.SYS_SHMGET, unix.SYS_SHMAT, unix.SYS_SHMDT, unix.SYS_SHMCTL,
		unix.SYS_MSGGET, unix.SYS_MSGSND, unix.SYS_MSGRCV, unix.SYS_MSGCTL,
		unix.SYS_SEMGET, unix.SYS_SEMOP, unix.SYS_SEMTIMEDOP, unix.SYS_SEMCTL,
		unix.SYS_MQ_OPEN, unix.SYS_MQ_UNLINK, unix.SYS_MQ_TIMEDSEND,
		unix.SYS_MQ_TIMEDRECEIVE, unix.SYS_MQ_NOTIFY, unix.SYS_MQ_GETSETATTR,
	} {
		p = append(p, ins(scEqual, nr, 0, 1), ins(scReturn, deny, 0, 0))
	}
	if len(tcpOnly)>0 && tcpOnly[0] {
		// Outbound TCP only; private UNIX stream pairs still allowed.
		// No listener or inbound accepted socket may create an alternate path.
		for _,nr:=range []uint32{unix.SYS_LISTEN,unix.SYS_ACCEPT,unix.SYS_ACCEPT4} {
			p=append(p,ins(scEqual,nr,0,1),ins(scReturn,deny,0,0))
		}
		// Reject TCP Fast Open send flags before a connect policy decision.
		for _,c:=range []struct{nr,offset uint32}{{unix.SYS_SENDTO,40},{unix.SYS_SENDMSG,32},{unix.SYS_SENDMMSG,40}} {
			p=append(p,ins(scEqual,c.nr,0,4),ins(scLoad,c.offset,0,0),
				ins(scSet,unix.MSG_FASTOPEN,0,1),ins(scReturn,deny,0,0),ins(scLoad,0,0,0))
		}
	}
	// clone3 passes a pointer; classic seccomp cannot inspect its flags.
	// ENOSYS preserves libc fallback to the filtered clone syscall.
	p = append(p, ins(scEqual, unix.SYS_CLONE3, 0, 1),
		ins(scReturn, uint32(scErrno)|uint32(unix.ENOSYS), 0, 0))
	const namespaceFlags = 0x7e020000 // NEWNS, NEWCGROUP, NEWUTS, NEWIPC, NEWUSER, NEWPID, NEWNET
	p = append(p,
		ins(scEqual, unix.SYS_CLONE, 0, 4),
		ins(scLoad, 16, 0, 0),
		ins(scSet, namespaceFlags, 0, 1),
		ins(scReturn, deny, 0, 0),
		ins(scReturn, scAllow, 0, 0),
	)
	// Strict guarded mode: no new externally addressable UNIX sockets.
	// Private connected stream pairs remain available for communication
	// within the same protection domain. Datagram pairs are not permitted.
	if len(tcpOnly)>0 && tcpOnly[0] {
		p=append(p,
			ins(scEqual,unix.SYS_SOCKET,0,13),
			ins(scLoad,16,0,0),
			ins(scEqual,unix.AF_INET,2,0),
			ins(scEqual,unix.AF_INET6,1,0),
			ins(scReturn,deny,0,0),
			ins(scLoad,24,0,0),
			ins(scAnd,0xf,0,0),
			ins(scEqual,unix.SOCK_STREAM,1,0),
			ins(scReturn,deny,0,0),
			ins(scLoad,32,0,0),
			ins(scEqual,0,2,0),
			ins(scEqual,unix.IPPROTO_TCP,1,0),
			ins(scReturn,deny,0,0),
			ins(scReturn,scAllow,0,0),
		)
	} else {
	p = append(p,
		ins(scEqual, unix.SYS_SOCKET, 0, 9),
		ins(scLoad, 16, 0, 0),
		ins(scEqual, unix.AF_INET, 2, 0),
		ins(scEqual, unix.AF_INET6, 1, 0),
		ins(scReturn, deny, 0, 0),
		ins(scLoad, 24, 0, 0),
		ins(scAnd, 0xf, 0, 0),
		ins(scEqual, unix.SOCK_RAW, 0, 1),
		ins(scReturn, deny, 0, 0),
		ins(scReturn, scAllow, 0, 0),
	)
	}
	p = append(p,
		ins(scEqual, unix.SYS_SOCKETPAIR, 0, 8),
		ins(scLoad, 16, 0, 0),
		ins(scEqual, unix.AF_UNIX, 1, 0),
		ins(scReturn, deny, 0, 0),
		ins(scLoad, 24, 0, 0),
		ins(scAnd, 0xf, 0, 0),
		ins(scEqual, unix.SOCK_STREAM, 1, 0),
		ins(scReturn, deny, 0, 0),
		ins(scReturn, scAllow, 0, 0),
	)
	return append(p, ins(scReturn, scAllow, 0, 0)), nil
}

// setpriv reads the raw sock_filter array before exec. A sealed anonymous
// file prevents mutation of the policy and avoids a persistent temp pathname.
func guardedSeccompFile(tcpOnly ...bool) (*os.File, error) {
	program, err := guardedSeccompProgram(tcpOnly...)
	if err != nil { return nil, err }
	fd, err := unix.MemfdCreate("gavel-seccomp", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil { return nil, err }
	f := os.NewFile(uintptr(fd), "gavel-seccomp")
	ok := false
	defer func() { if !ok { f.Close() } }()
	if err := binary.Write(f, binary.LittleEndian, program); err != nil { return nil, err }
	if err := f.Chmod(0444); err != nil { return nil, err }
	if _, err := unix.FcntlInt(f.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL); err != nil { return nil, err }
	if _, err := f.Seek(0, 0); err != nil { return nil, err }
	ok = true
	return f, nil
}
