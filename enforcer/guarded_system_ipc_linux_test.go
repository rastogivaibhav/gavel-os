//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	gavelIPCPrivate = 0
	gavelIPCCreate = 01000
	gavelIPCRmid = 0
	gavelIPCNowait = 04000
	gavelSemGetval = 12 // Linux semctl GETVAL
)

type gavelIPCMessage struct {
	Kind int64 // native long on supported 64-bit ABIs
	Data [8]byte
}
type gavelSemOperation struct {
	Number uint16
	Delta int16
	Flags int16
}

func gavelIPCCall(nr uintptr, args ...uintptr) (uintptr,error) {
	var a [6]uintptr
	copy(a[:],args)
	v,_,errno:=unix.Syscall6(nr,a[0],a[1],a[2],a[3],a[4],a[5])
	if errno!=0{return v,errno}
	return v,nil
}

// Pointer-bearing syscalls are called directly so the Go runtime keeps
// pointed-to objects alive for the duration of the syscall.
func gavelMsgSend(id int, text string) error {
	m:=gavelIPCMessage{Kind:1}
	copy(m.Data[:],text)
	_,_,e:=unix.Syscall6(unix.SYS_MSGSND,uintptr(id),uintptr(unsafe.Pointer(&m)),8,gavelIPCNowait,0,0)
	if e!=0{return e};return nil
}
func gavelMsgReceive(id int)(string,error){
	var m gavelIPCMessage
	n,_,e:=unix.Syscall6(unix.SYS_MSGRCV,uintptr(id),uintptr(unsafe.Pointer(&m)),8,0,gavelIPCNowait,0)
	if e!=0{return "",e}
	return strings.TrimRight(string(m.Data[:n]),"\x00"),nil
}
func gavelSemIncrement(id int)error{
	op:=gavelSemOperation{Delta:1,Flags:gavelIPCNowait}
	_,_,e:=unix.Syscall6(unix.SYS_SEMOP,uintptr(id),uintptr(unsafe.Pointer(&op)),1,0,0,0)
	if e!=0{return e};return nil
}
func gavelMQOpen(name string,flags int,mode uint32)(int,error){
	p,err:=unix.BytePtrFromString(name);if err!=nil{return -1,err}
	// Linux raw mq_open uses a name without the leading slash.
	attr:=[8]int64{0,4,64,0}
	fd,_,e:=unix.Syscall6(unix.SYS_MQ_OPEN,uintptr(unsafe.Pointer(p)),uintptr(flags),uintptr(mode),uintptr(unsafe.Pointer(&attr)),0,0)
	if e!=0{return -1,e};return int(fd),nil
}
func gavelMQUnlink(name string)error{
	p,err:=unix.BytePtrFromString(name);if err!=nil{return err}
	_,_,e:=unix.Syscall6(unix.SYS_MQ_UNLINK,uintptr(unsafe.Pointer(p)),0,0,0,0,0)
	if e!=0{return e};return nil
}
func gavelMQSend(fd int,text string)error{
	b:=[]byte(text)
	_,_,e:=unix.Syscall6(unix.SYS_MQ_TIMEDSEND,uintptr(fd),uintptr(unsafe.Pointer(&b[0])),uintptr(len(b)),0,0,0)
	if e!=0{return e};return nil
}
func gavelMQReceive(fd int)(string,error){
	var b [64]byte
	n,_,e:=unix.Syscall6(unix.SYS_MQ_TIMEDRECEIVE,uintptr(fd),uintptr(unsafe.Pointer(&b[0])),uintptr(len(b)),0,0,0)
	if e!=0{return "",e};return string(b[:n]),nil
}

func TestGuardedSystemIPCProbe(t *testing.T){
	mode:=os.Getenv("GAVEL_SYSIPC_MODE")
	if mode==""{t.Skip("isolated system IPC probe")}
	readID:=func(key string)int{v,e:=strconv.Atoi(os.Getenv(key));if e!=nil||v<0{t.Fatalf("invalid fixture id %s: %v",key,e)};return v}
	shm,msg,sem:=readID("GAVEL_SYSIPC_SHM"),readID("GAVEL_SYSIPC_MSG"),readID("GAVEL_SYSIPC_SEM")
	name:=os.Getenv("GAVEL_SYSIPC_MQ")
	if mode=="control"{
		b,e:=unix.SysvShmAttach(shm,0,0);if e!=nil{t.Fatal(e)}
		if string(b[:4])!="seed"{t.Fatal("unexpected shared memory seed")}
		copy(b[:4],"ctrl")
		if e:=unix.SysvShmDetach(b);e!=nil{t.Fatal(e)}
		if v,e:=gavelMsgReceive(msg);e!=nil||v!="seed"{t.Fatalf("message control: %q %v",v,e)}
		if e:=gavelMsgSend(msg,"ctrl");e!=nil{t.Fatal(e)}
		if e:=gavelSemIncrement(sem);e!=nil{t.Fatal(e)}
		fd,e:=gavelMQOpen(name,unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC,0);if e!=nil{t.Fatal(e)};defer unix.Close(fd)
		if v,e:=gavelMQReceive(fd);e!=nil||v!="seed"{t.Fatalf("POSIX queue control: %q %v",v,e)}
		if e:=gavelMQSend(fd,"ctrl");e!=nil{t.Fatal(e)}
		return
	}
	deny:=func(op string,e error){t.Helper();if !errors.Is(e,unix.EPERM){t.Fatalf("%s: expected seccomp EPERM, got %v",op,e)}}
	// Real fixture identifiers, not invalid arguments; no writes should reach
	// the shared objects. Direct attach also tests the actual shmat syscall.
	addr,e:=gavelIPCCall(unix.SYS_SHMAT,uintptr(shm),0,0)
	if e==nil{_,_=gavelIPCCall(unix.SYS_SHMDT,addr)}
	deny("System V shmat",e)
	_,e=gavelIPCCall(unix.SYS_SHMCTL,uintptr(shm),gavelIPCRmid,0);deny("System V shmctl removal",e)
	deny("System V message send",gavelMsgSend(msg,"bad"))
	_,e=gavelMsgReceive(msg);deny("System V message receive",e)
	deny("System V semaphore operation",gavelSemIncrement(sem))
	_,e=gavelIPCCall(unix.SYS_SEMCTL,uintptr(sem),0,gavelSemGetval,0);deny("System V semaphore read",e)
	fd,e:=gavelMQOpen(name,unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC,0)
	if fd>=0{unix.Close(fd)}
	deny("POSIX message queue open",e)
	deny("POSIX message queue unlink",gavelMQUnlink(name))
	b,e:=unix.Mmap(-1,0,4096,unix.PROT_READ|unix.PROT_WRITE,unix.MAP_PRIVATE|unix.MAP_ANON)
	if e!=nil{t.Fatal(e)}
	b[0]=42;if b[0]!=42{t.Fatal("private anonymous memory failed")}
	if e:=unix.Munmap(b);e!=nil{t.Fatal(e)}
	r,w,e:=os.Pipe();if e!=nil{t.Fatal(e)};defer r.Close();defer w.Close()
	if _,e:=w.Write([]byte("P"));e!=nil{t.Fatal(e)}
	var p [1]byte;if n,e:=r.Read(p[:]);e!=nil||n!=1||p[0]!='P'{t.Fatalf("private pipe: %d %v",n,e)}
	if mode=="guarded"{
		exe,e:=os.Executable();if e!=nil{t.Fatal(e)}
		cmd:=exec.Command(exe,"-test.run=^TestGuardedSystemIPCProbe$","-test.v")
		cmd.Env=append(os.Environ(),"GAVEL_SYSIPC_MODE=descendant")
		cmd.Stdin,cmd.Stdout,cmd.Stderr=os.Stdin,os.Stdout,os.Stderr
		if e:=cmd.Run();e!=nil{t.Fatalf("descendant IPC proof: %v",e)}
	}
	t.Log("KERNEL PROOF: external System V IPC and POSIX message queue denied; private memory and pipe allowed")
}

func TestKernelGuardedSystemIPC(t *testing.T){
	if os.Getenv("GAVEL_RUN_KERNEL_TESTS")!="1"{t.Skip("requires isolated privileged VM")}
	if os.Geteuid()!=0{t.Fatal("requires root")}
	shm,e:=unix.SysvShmGet(gavelIPCPrivate,4096,gavelIPCCreate|0666);if e!=nil{t.Fatal(e)}
	defer unix.SysvShmCtl(shm,gavelIPCRmid,nil)
	b,e:=unix.SysvShmAttach(shm,0,0);if e!=nil{t.Fatal(e)};defer unix.SysvShmDetach(b)
	copy(b[:4],"seed")
	msg,e:=gavelIPCCall(unix.SYS_MSGGET,gavelIPCPrivate,gavelIPCCreate|0666);if e!=nil{t.Fatal(e)}
	defer gavelIPCCall(unix.SYS_MSGCTL,msg,gavelIPCRmid,0)
	if e:=gavelMsgSend(int(msg),"seed");e!=nil{t.Fatal(e)}
	sem,e:=gavelIPCCall(unix.SYS_SEMGET,gavelIPCPrivate,1,gavelIPCCreate|0666);if e!=nil{t.Fatal(e)}
	defer gavelIPCCall(unix.SYS_SEMCTL,sem,0,gavelIPCRmid,0)
	name:=fmt.Sprintf("gavel-ipc-%d-%d",os.Getpid(),time.Now().UnixNano())
	old:=unix.Umask(0)
	mq,e:=gavelMQOpen(name,unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC,0666)
	unix.Umask(old)
	if e!=nil{t.Fatal(e)}
	defer gavelMQUnlink(name);defer unix.Close(mq)
	if e:=gavelMQSend(mq,"seed");e!=nil{t.Fatal(e)}
	t.Setenv("GAVEL_SYSIPC_SHM",strconv.Itoa(shm))
	t.Setenv("GAVEL_SYSIPC_MSG",strconv.Itoa(int(msg)))
	t.Setenv("GAVEL_SYSIPC_SEM",strconv.Itoa(int(sem)))
	t.Setenv("GAVEL_SYSIPC_MQ",name)
	exe,e:=os.Executable();if e!=nil{t.Fatal(e)}
	argv:=[]string{exe,"-test.run=^TestGuardedSystemIPCProbe$","-test.v"}
	control:=exec.Command(argv[0],argv[1:]...)
	control.Env=append(os.Environ(),"GAVEL_SYSIPC_MODE=control")
	control.SysProcAttr=&syscall.SysProcAttr{Credential:&syscall.Credential{Uid:421338,Gid:421338}}
	if out,e:=control.CombinedOutput();e!=nil||!strings.Contains(string(out),"PASS: TestGuardedSystemIPCProbe"){t.Fatalf("unguarded positive control: %v %s",e,out)}
	if string(b[:4])!="ctrl"{t.Fatal("positive control did not alter shared memory")}
	t.Setenv("GAVEL_MACHINE_KEY","")
	t.Setenv("GAVEL_MONITORED_PIDS","")
	t.Setenv("GAVEL_BLOCKED_IPS","127.0.0.2")
	t.Setenv("GAVEL_AGENT_UID","421338")
	t.Setenv("GAVEL_AGENT_GID","421338")
	t.Setenv("GAVEL_SYSIPC_MODE","guarded")
	if e:=runGuardedAgent(argv);e!=nil{t.Fatal(e)}
	if string(b[:4])!="ctrl"{t.Fatal("guarded shared memory changed")}
	if v,e:=gavelMsgReceive(int(msg));e!=nil||v!="ctrl"{t.Fatalf("host message changed: %q %v",v,e)}
	if _,e:=gavelMsgReceive(int(msg));!errors.Is(e,unix.ENOMSG){t.Fatalf("unexpected extra System V message: %v",e)}
	if v,e:=gavelIPCCall(unix.SYS_SEMCTL,sem,0,gavelSemGetval,0);e!=nil||v!=1{t.Fatalf("host semaphore changed: %d %v",v,e)}
	if v,e:=gavelMQReceive(mq);e!=nil||v!="ctrl"{t.Fatalf("host POSIX message changed: %q %v",v,e)}
	if _,e:=gavelMQReceive(mq);!errors.Is(e,unix.EAGAIN){t.Fatalf("unexpected extra POSIX message: %v",e)}
	check,e:=gavelMQOpen(name,unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC,0);if e!=nil{t.Fatalf("queue name removed: %v",e)};unix.Close(check)
	t.Log("KERNEL PROOF: shared IPC fixtures remained intact; positive controls and descendants verified")
}
