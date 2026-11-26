//go:build linux

package main

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func TestGuardedIntegrityProbe(t *testing.T) {
	mode:=os.Getenv("GAVEL_INTEGRITY_PROBE")
	if mode=="" {t.Skip("guarded integrity probe")}
	if os.Geteuid()==0{t.Fatal("probe must be unprivileged")}
	data,err:=os.ReadFile("/proc/self/cgroup");if err!=nil{t.Fatal(err)}
	name:=""
	for _,line:=range strings.Split(string(data),"\n"){
		if strings.HasPrefix(line,"0::"){name=filepath.Base(strings.TrimPrefix(line,"0::"))}
	}
	base,err:=guardedPinPath(name);if err!=nil{t.Fatal(err)}
	deny:=func(op string,err error){t.Helper();if !errors.Is(err,unix.EPERM)&&!errors.Is(err,unix.EACCES){t.Fatalf("%s expected access denial: %v",op,err)}}
	for _,suffix:=range guardedNetworkPinSuffixes{
		pin:=base+suffix
		deny("unlink pin",os.Remove(pin))
		deny("rename pin",os.Rename(pin,pin+"_test"))
	}
	if err:=recoverGuardedAgent(name);err==nil{t.Fatal("unprivileged recovery accepted")}
	_,_,errno:=unix.RawSyscall6(unix.SYS_BPF,0,0,0,0,0,0)
	if errno!=unix.EPERM{t.Fatalf("BPF syscall policy: %v",errno)}
	allow,err:=net.DialTimeout("tcp4",os.Getenv("GAVEL_INTEGRITY_ALLOW"),time.Second)
	if err!=nil{t.Fatal(err)};allow.Close()
	blocked,err:=net.DialTimeout("tcp4",os.Getenv("GAVEL_INTEGRITY_DENY"),time.Second)
	if blocked!=nil{blocked.Close()}
	deny("network after tamper",err)
	if mode=="parent"{
		exe,err:=os.Executable();if err!=nil{t.Fatal(err)}
		cmd:=exec.Command(exe,"-test.run=^TestGuardedIntegrityProbe$","-test.v")
		cmd.Env=append(os.Environ(),"GAVEL_INTEGRITY_PROBE=descendant")
		cmd.Stdin,cmd.Stdout,cmd.Stderr=os.Stdin,os.Stdout,os.Stderr
		if err:=cmd.Run();err!=nil{t.Fatal(err)}
	}
	t.Log("KERNEL PROOF: guarded link changes denied and network enforcement remained active")
}

func TestKernelGuardedPolicyIntegrity(t *testing.T){
	if os.Getenv("GAVEL_RUN_KERNEL_TESTS")!="1"{t.Skip("requires isolated privileged VM")}
	if os.Geteuid()!=0{t.Fatal("requires root")}
	ip,err:=parseIPv4("127.0.0.2");if err!=nil{t.Fatal(err)}
	ip6,err:=parseIPv6("::1");if err!=nil{t.Fatal(err)}
	keys,err:=parseGuardedTCPAllow(`["127.0.0.1:80"]`);if err!=nil{t.Fatal(err)}
	for _,strict:=range []bool{false,true}{
		objects,err:=loadLinuxEnforcerObjects(true,strict);if err!=nil{t.Fatal(err)}
		defer objects.Close()
		// Test all maps using host-owned fixture handles. This is stronger
		// than checking unprivileged BPF syscall refusal alone.
		type entry struct{m *ebpf.Map;key,value,other any; read func()bool;hash bool}
		readByte:=func(m *ebpf.Map,k any)func()bool{return func()bool{var v uint8;return m.Lookup(k,&v)==nil&&v==1}}
		pid:=uint32(42)
		proxy:=LinuxProxyConfig{Enabled:1}
		entries:=[]entry{
			{objects.MonitoredPIDs,pid,uint8(1),uint8(0),readByte(objects.MonitoredPIDs,pid),true},
			{objects.BlockedIPv4,ip,uint8(1),uint8(0),readByte(objects.BlockedIPv4,ip),true},
			{objects.BlockedIPv6,ip6,uint8(1),uint8(0),readByte(objects.BlockedIPv6,ip6),true},
			{objects.AllowedTCP,keys[0],uint8(1),uint8(0),readByte(objects.AllowedTCP,keys[0]),true},
			{objects.ProxyConfig,uint32(0),proxy,LinuxProxyConfig{},func()bool{var v LinuxProxyConfig;return objects.ProxyConfig.Lookup(uint32(0),&v)==nil&&v==proxy},false},
		}
		for _,e:=range entries{
			if err:=e.m.Put(e.key,e.other);err!=nil{t.Fatalf("pre-freeze initial update: %v",err)}
			if err:=e.m.Put(e.key,e.value);err!=nil{t.Fatalf("pre-freeze positive update: %v",err)}
			if !e.read(){t.Fatal("positive control value missing")}
		}
		if err:=objects.freezeGuardedPolicy();err!=nil{t.Fatal(err)}
		for _,e:=range entries{
			if err:=e.m.Put(e.key,e.other);!errors.Is(err,unix.EPERM){t.Fatalf("frozen map update expected EPERM: %v",err)}
			if e.hash{if err:=e.m.Delete(e.key);!errors.Is(err,unix.EPERM){t.Fatalf("frozen map delete expected EPERM: %v",err)}}
			if !e.read(){t.Fatal("frozen policy value changed")}
		}
		t.Logf("KERNEL PROOF: five maps frozen, values unchanged, strict=%t",strict)
	}
	a,err:=net.ListenTCP("tcp4",&net.TCPAddr{IP:net.ParseIP("127.0.0.1")});if err!=nil{t.Fatal(err)};defer a.Close()
	b,err:=net.ListenTCP("tcp4",&net.TCPAddr{IP:net.ParseIP("127.0.0.2")});if err!=nil{t.Fatal(err)};defer b.Close()
	t.Setenv("GAVEL_MACHINE_KEY","")
	t.Setenv("GAVEL_MONITORED_PIDS","")
	t.Setenv("GAVEL_BLOCKED_IPS","127.0.0.2")
	t.Setenv("GAVEL_AGENT_UID","421341")
	t.Setenv("GAVEL_AGENT_GID","421341")
	t.Setenv("GAVEL_INTEGRITY_ALLOW",a.Addr().String())
	t.Setenv("GAVEL_INTEGRITY_DENY",b.Addr().String())
	t.Setenv("GAVEL_INTEGRITY_PROBE","parent")
	exe,err:=os.Executable();if err!=nil{t.Fatal(err)}
	if err:=runGuardedAgent([]string{exe,"-test.run=^TestGuardedIntegrityProbe$","-test.v"});err!=nil{t.Fatal(err)}
	if err:=a.SetDeadline(time.Now().Add(2*time.Second));err!=nil{t.Fatal(err)}
	for i:=0;i<2;i++{c,err:=a.AcceptTCP();if err!=nil{t.Fatal(err)};c.Close()}
	if err:=b.SetDeadline(time.Now().Add(150*time.Millisecond));err!=nil{t.Fatal(err)}
	c,err:=b.AcceptTCP();if c!=nil{c.Close();t.Fatal("forbidden receiver observed traffic")}
	var ne net.Error;if !errors.As(err,&ne)||!ne.Timeout(){t.Fatalf("negative receiver observation: %v",err)}
	t.Log("KERNEL PROOF: policy active after parent and descendant tamper probes")
}
