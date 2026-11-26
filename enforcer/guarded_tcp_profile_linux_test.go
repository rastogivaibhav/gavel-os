//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestGuardedTCPProfileValidation(t *testing.T){
	keys,err:=parseGuardedTCPAllow(`["127.0.0.1:443","[::ffff:127.0.0.1]:443","[::1]:443"]`)
	if err!=nil||len(keys)!=2||keys[0][10]!=255||keys[0][11]!=255||keys[0][16]!=1||keys[0][17]!=187{t.Fatalf("canonical endpoint keys: %x %v",keys,err)}
	for _,raw:=range []string{"","null","{}",`["example.com:443"]`,`["127.0.0.1:0"]`,`["0.0.0.0:80"]`,`["[fe80::1%lo]:80"]`}{if _,err:=parseGuardedTCPAllow(raw);err==nil{t.Fatalf("invalid list accepted: %s",raw)}}
	t.Setenv(guardedNetProfileEnv,"tcp-services")
	t.Setenv(guardedTCPAllowEnv,"[]")
	t.Setenv("GAVEL_MACHINE_KEY","")
	cfg:=LinuxEnforcerConfig{ProtectAll:true}
	if err:=configureGuardedTCPProfile(&cfg);err!=nil||!cfg.TCPOnly||!linuxPolicyConfigured(cfg){t.Fatalf("empty explicit deny-all: %+v %v",cfg,err)}
	cfg=LinuxEnforcerConfig{ProtectAll:true,BlockedIPv4:[]uint32{1}}
	if err:=configureGuardedTCPProfile(&cfg);err==nil{t.Fatal("conflicting policy accepted")}
	t.Setenv("GAVEL_MACHINE_KEY","synthetic")
	if err:=configureGuardedTCPProfile(&LinuxEnforcerConfig{ProtectAll:true});err==nil{t.Fatal("control plane conflict accepted")}
}

func TestGuardedTCPServiceProbe(t *testing.T){
	mode:=os.Getenv("GAVEL_TCP_TEST_MODE")
	if mode==""{t.Skip("isolated TCP service probe")}
	for _,c:=range networkMediationCases{
		for _,side:=range []string{"ALLOW","DENY"}{
			addr:=mediationAddress(t,c,os.Getenv("GAVEL_TCP_TEST_"+c.family+"_"+side))
			fd:=mediationSocket(t,c,unix.SOCK_STREAM,unix.IPPROTO_TCP)
			err:=unix.Connect(fd,addr)
			denied:=mode!="control"&&(side=="DENY"||mode=="empty")
			if denied{
				if !errors.Is(err,unix.EPERM)&&!errors.Is(err,unix.EACCES){t.Fatalf("%s %s expected denial: %v",c.name,side,err)}
			}else if err!=nil{t.Fatalf("%s %s expected connect: %v",c.name,side,err)}
		}
	}
	if mode=="control"{return}
	for _,family:=range []int{unix.AF_INET,unix.AF_INET6}{
		fd,err:=unix.Socket(family,unix.SOCK_DGRAM|unix.SOCK_CLOEXEC,unix.IPPROTO_UDP)
		if fd>=0{unix.Close(fd)}
		if !errors.Is(err,unix.EPERM){t.Fatalf("UDP socket expected denial: %v",err)}
	}
	fd,err:=unix.Socket(unix.AF_INET,unix.SOCK_STREAM|unix.SOCK_CLOEXEC,0);if err!=nil{t.Fatal(err)}
	defer unix.Close(fd)
	if err:=unix.Listen(fd,1);!errors.Is(err,unix.EPERM){t.Fatalf("listen expected denial: %v",err)}
	checkPrivateIPC(t)
	if mode=="guarded"{
		exe,err:=os.Executable();if err!=nil{t.Fatal(err)}
		cmd:=exec.Command(exe,"-test.run=^TestGuardedTCPServiceProbe$","-test.v")
		cmd.Env=append(os.Environ(),"GAVEL_TCP_TEST_MODE=descendant")
		cmd.Stdin,cmd.Stdout,cmd.Stderr=os.Stdin,os.Stdout,os.Stderr
		if err:=cmd.Run();err!=nil{t.Fatal(err)}
	}
	t.Log("KERNEL PROOF: exact TCP services permitted; other ports and UDP/listen denied")
}

func TestKernelGuardedTCPServiceProfile(t *testing.T){
	if os.Getenv("GAVEL_RUN_KERNEL_TESTS")!="1"{t.Skip("requires isolated privileged VM")}
	if os.Geteuid()!=0{t.Fatal("requires root")}
	type pair struct{a,b *net.TCPListener; count int}
	var pairs []pair
	var allowed []string
	for _,family:=range []string{"4","6"}{
		host:="127.0.0.1";count:=2
		if family=="6"{host="::1";count=1}
		open:=func()*net.TCPListener{
			l,err:=net.ListenTCP("tcp"+family,&net.TCPAddr{IP:net.ParseIP(host)})
			if err!=nil{t.Fatal(err)};t.Cleanup(func(){l.Close()});return l
		}
		a,b:=open(),open()
		pairs=append(pairs,pair{a,b,count})
		allowed=append(allowed,a.Addr().String())
		t.Setenv("GAVEL_TCP_TEST_"+family+"_ALLOW",a.Addr().String())
		t.Setenv("GAVEL_TCP_TEST_"+family+"_DENY",b.Addr().String())
	}
	assert:=func(l *net.TCPListener,n int){
		t.Helper()
		for i:=0;i<n;i++{if err:=l.SetDeadline(time.Now().Add(2*time.Second));err!=nil{t.Fatal(err)};c,err:=l.AcceptTCP();if err!=nil{t.Fatal(err)};c.Close()}
		if err:=l.SetDeadline(time.Now().Add(100*time.Millisecond));err!=nil{t.Fatal(err)}
		c,err:=l.AcceptTCP();if c!=nil{c.Close();t.Fatal("unexpected connection")}
		var ne net.Error;if !errors.As(err,&ne)||!ne.Timeout(){t.Fatalf("receiver observation: %v",err)}
	}
	exe,err:=os.Executable();if err!=nil{t.Fatal(err)}
	argv:=[]string{exe,"-test.run=^TestGuardedTCPServiceProbe$","-test.v"}
	control:=exec.Command(argv[0],argv[1:]...)
	control.Env=append(os.Environ(),"GAVEL_TCP_TEST_MODE=control")
	control.SysProcAttr=&syscall.SysProcAttr{Credential:&syscall.Credential{Uid:421340,Gid:421340}}
	if out,err:=control.CombinedOutput();err!=nil||!strings.Contains(string(out),"PASS: TestGuardedTCPServiceProbe"){t.Fatalf("positive control: %v %s",err,out)}
	for _,p:=range pairs{assert(p.a,p.count);assert(p.b,p.count)}
	t.Setenv("GAVEL_MACHINE_KEY","")
	t.Setenv("GAVEL_MONITORED_PIDS","")
	t.Setenv("GAVEL_BLOCKED_IPS","")
	t.Setenv("GAVEL_BLOCKED_IPV6","")
	t.Setenv("GAVEL_PROXY_IPV4","")
	t.Setenv("GAVEL_PROXY_PORT","")
	t.Setenv("GAVEL_AGENT_UID","421340")
	t.Setenv("GAVEL_AGENT_GID","421340")
	t.Setenv(guardedNetProfileEnv,"tcp-services")
	raw,err:=json.Marshal(allowed);if err!=nil{t.Fatal(err)}
	t.Setenv(guardedTCPAllowEnv,string(raw))
	t.Setenv("GAVEL_TCP_TEST_MODE","guarded")
	if err:=runGuardedAgent(argv);err!=nil{t.Fatal(err)}
	for _,p:=range pairs{assert(p.a,2*p.count);assert(p.b,0)}
	t.Setenv(guardedTCPAllowEnv,"[]")
	t.Setenv("GAVEL_TCP_TEST_MODE","empty")
	if err:=runGuardedAgent(argv);err!=nil{t.Fatal(err)}
	for _,p:=range pairs{assert(p.a,0);assert(p.b,0)}
}
