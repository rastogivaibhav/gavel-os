//go:build linux

package main

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type networkMediationCase struct {
	name, family string
	domain int
	mapped bool
}

var networkMediationCases = []networkMediationCase{
	{"native4","4",unix.AF_INET,false},
	{"native6","6",unix.AF_INET6,false},
	{"mapped4","4",unix.AF_INET6,true},
}

func mediationAddress(t *testing.T, c networkMediationCase, value string) unix.Sockaddr {
	t.Helper()
	host, portText, err := net.SplitHostPort(value)
	if err != nil { t.Fatal(err) }
	port, err := strconv.Atoi(portText)
	ip := net.ParseIP(host)
	if err != nil || port <= 0 || ip == nil { t.Fatalf("invalid loopback test address %q",value) }
	if c.domain == unix.AF_INET {
		a := &unix.SockaddrInet4{Port:port}
		copy(a.Addr[:],ip.To4())
		return a
	}
	a := &unix.SockaddrInet6{Port:port}
	copy(a.Addr[:],ip.To16()) // preserves ::ffff/96 for mapped IPv4
	return a
}

func mediationSocket(t *testing.T,c networkMediationCase,kind,proto int) int {
	t.Helper()
	fd,err:=unix.Socket(c.domain,kind|unix.SOCK_CLOEXEC,proto)
	if err!=nil { t.Fatal(err) }
	t.Cleanup(func(){ unix.Close(fd) })
	if c.domain==unix.AF_INET6 {
		only:=1
		if c.mapped { only=0 }
		if err:=unix.SetsockoptInt(fd,unix.IPPROTO_IPV6,unix.IPV6_V6ONLY,only);err!=nil {t.Fatal(err)}
	}
	return fd
}

func mediationProbe(t *testing.T,control bool) {
	t.Helper()
	for _,c:=range networkMediationCases {
		t.Run(c.name,func(t *testing.T){
			// Unguarded controls exercise the exact prohibited destination.
			// Guarded tests exercise allowed and denied destinations.
			check:=func(name string,blocked bool,err error){
				t.Helper()
				if blocked && !control {
					if !errors.Is(err,unix.EPERM)&&!errors.Is(err,unix.EACCES){t.Fatalf("%s: expected kernel denial, got %v",name,err)}
				} else if err!=nil {t.Fatalf("%s: expected success, got %v",name,err)}
			}
			address:=func(proto,side string)unix.Sockaddr{
				return mediationAddress(t,c,os.Getenv("GAVEL_MED_"+proto+c.family+"_"+side))
			}
			for _,side:=range []string{"ALLOW","DENY"} {
				blocked:=side=="DENY"
				tcp:=mediationSocket(t,c,unix.SOCK_STREAM,unix.IPPROTO_TCP)
				check("TCP connect",blocked,unix.Connect(tcp,address("TCP",side)))
				fd:=mediationSocket(t,c,unix.SOCK_DGRAM,unix.IPPROTO_UDP)
				err:=unix.Connect(fd,address("UDP",side))
				check("UDP connect",blocked,err)
				if err==nil {
					payload:=[]byte(c.name+"-connected")
					n,err:=unix.Write(fd,payload)
					check("connected UDP write",blocked,err)
					if n!=len(payload){t.Fatalf("short write %d",n)}
					// A connected allowed socket must not override its peer
					// to a blocked destination using an explicit address.
					if !blocked {
						target:=address("UDP","DENY")
						check("connected sendto override",true,unix.Sendto(fd,[]byte(c.name+"-override-to"),0,target))
						_,err:=unix.SendmsgN(fd,[]byte(c.name+"-override-msg"),nil,target,0)
						check("connected sendmsg override",true,err)
					}
				}
				free:=mediationSocket(t,c,unix.SOCK_DGRAM,unix.IPPROTO_UDP)
				target:=address("UDP",side)
				check("unconnected sendto",blocked,unix.Sendto(free,[]byte(c.name+"-to"),0,target))
				_,err=unix.SendmsgN(free,[]byte(c.name+"-msg"),nil,target,0)
				check("unconnected sendmsg",blocked,err)
			}
			t.Log("KERNEL PROBE: TCP, connected UDP, explicit UDP overrides and unconnected UDP",c.name)
		})
	}
}

func TestGuardedNetworkMediationProbe(t *testing.T) {
	mode:=os.Getenv("GAVEL_MED_MODE")
	if mode=="" { t.Skip("isolated network mediation probe") }
	mediationProbe(t,mode=="control")
	if mode=="guarded" {
		exe,err:=os.Executable();if err!=nil {t.Fatal(err)}
		cmd:=exec.Command(exe,"-test.run=^TestGuardedNetworkMediationProbe$","-test.v")
		cmd.Env=append(os.Environ(),"GAVEL_MED_MODE=descendant")
		cmd.Stdin,cmd.Stdout,cmd.Stderr=os.Stdin,os.Stdout,os.Stderr
		if err:=cmd.Run();err!=nil {t.Fatalf("descendant proof: %v",err)}
	}
}

func TestKernelGuardedNetworkMediation(t *testing.T) {
	if os.Getenv("GAVEL_RUN_KERNEL_TESTS")!="1" {t.Skip("requires isolated privileged VM")}
	if os.Geteuid()!=0 {t.Fatal("requires root")}
	a6,b6:=ipv6ProofListeners(t)
	a4,err:=net.Listen("tcp4","127.0.0.1:0");if err!=nil {t.Fatal(err)};defer a4.Close()
	b4,err:=net.Listen("tcp4","127.0.0.2:0");if err!=nil {t.Fatal(err)};defer b4.Close()
	udp:=setupUDPProof(t)
	type listeners struct{family string; a,b *net.TCPListener; u udpProofPair; names []string}
	pairs:=[]listeners{
		{"4",a4.(*net.TCPListener),b4.(*net.TCPListener),udp[0],[]string{"native4","mapped4"}},
		{"6",a6.(*net.TCPListener),b6.(*net.TCPListener),udp[1],[]string{"native6"}},
	}
	for _,p:=range pairs {
		t.Setenv("GAVEL_MED_TCP"+p.family+"_ALLOW",p.a.Addr().String())
		t.Setenv("GAVEL_MED_TCP"+p.family+"_DENY",p.b.Addr().String())
		t.Setenv("GAVEL_MED_UDP"+p.family+"_ALLOW",p.u.allowed.LocalAddr().String())
		t.Setenv("GAVEL_MED_UDP"+p.family+"_DENY",p.u.denied.LocalAddr().String())
	}
	assertTCP:=func(l *net.TCPListener,count int){
		t.Helper()
		for i:=0;i<count;i++ {
			if err:=l.SetDeadline(time.Now().Add(2*time.Second));err!=nil {t.Fatal(err)}
			c,err:=l.AcceptTCP();if err!=nil {t.Fatalf("missing expected TCP connection: %v",err)};c.Close()
		}
		if err:=l.SetDeadline(time.Now().Add(150*time.Millisecond));err!=nil {t.Fatal(err)}
		c,err:=l.AcceptTCP();if c!=nil {c.Close();t.Fatal("unexpected TCP connection")}
		var ne net.Error;if !errors.As(err,&ne)||!ne.Timeout(){t.Fatalf("TCP receiver observation: %v",err)}
	}
	assertUDP:=func(l *net.UDPConn,want map[string]int){
		t.Helper()
		var buf [128]byte
		total:=0;for _,n:=range want{total+=n}
		for i:=0;i<total;i++{
			if err:=l.SetReadDeadline(time.Now().Add(2*time.Second));err!=nil {t.Fatal(err)}
			n,_,err:=l.ReadFromUDP(buf[:]);if err!=nil{t.Fatalf("missing expected UDP payload: %v",err)}
			key:=string(buf[:n]);if want[key]<=0{t.Fatalf("unexpected UDP payload %q",key)};want[key]--
		}
		if err:=l.SetReadDeadline(time.Now().Add(150*time.Millisecond));err!=nil{t.Fatal(err)}
		n,_,err:=l.ReadFromUDP(buf[:]);var ne net.Error
		if !errors.As(err,&ne)||!ne.Timeout(){t.Fatalf("unexpected UDP receipt n=%d err=%v",n,err)}
	}
	want:=func(names []string,probes int,overrides bool)map[string]int{
		out:=map[string]int{}
		for _,name:=range names{
			for _,suffix:=range []string{"-connected","-to","-msg"}{out[name+suffix]=probes}
			if overrides{out[name+"-override-to"]=probes;out[name+"-override-msg"]=probes}
		};return out
	}
	exe,err:=os.Executable();if err!=nil{t.Fatal(err)}
	cmd:=exec.Command(exe,"-test.run=^TestGuardedNetworkMediationProbe$","-test.v")
	cmd.Env=append(os.Environ(),"GAVEL_MED_MODE=control")
	cmd.SysProcAttr=&syscall.SysProcAttr{Credential:&syscall.Credential{Uid:65534,Gid:65534}}
	if out,err:=cmd.CombinedOutput();err!=nil||!strings.Contains(string(out),"PASS: TestGuardedNetworkMediationProbe"){t.Fatalf("unguarded receiver control: %v %s",err,out)}
	for _,p:=range pairs{
		assertTCP(p.a,len(p.names));assertTCP(p.b,len(p.names))
		assertUDP(p.u.allowed,want(p.names,1,false));assertUDP(p.u.denied,want(p.names,1,true))
	}
	t.Setenv("GAVEL_MACHINE_KEY","")
	t.Setenv("GAVEL_MONITORED_PIDS","")
	t.Setenv("GAVEL_BLOCKED_IPS","127.0.0.2")
	t.Setenv("GAVEL_BLOCKED_IPV6","fd00:6761:7665:6c::2")
	t.Setenv("GAVEL_PROXY_IPV4","")
	t.Setenv("GAVEL_PROXY_PORT","")
	t.Setenv("GAVEL_AGENT_UID","65534")
	t.Setenv("GAVEL_AGENT_GID","65534")
	t.Setenv("GAVEL_MED_MODE","guarded")
	if err:=runGuardedAgent([]string{exe,"-test.run=^TestGuardedNetworkMediationProbe$","-test.v"});err!=nil{t.Fatal(err)}
	for _,p:=range pairs{
		assertTCP(p.a,2*len(p.names));assertTCP(p.b,0)
		assertUDP(p.u.allowed,want(p.names,2,false));assertUDP(p.u.denied,nil)
	}
	t.Log("KERNEL PROOF: native and mapped TCP/UDP allowed controls observed; prohibited receivers observed zero effects")
}
