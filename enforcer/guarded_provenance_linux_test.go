//go:build linux

package main

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGuardedPolicyDigest(t *testing.T){
	f,err:=guardedSeccompFile(false);if err!=nil{t.Fatal(err)};defer f.Close()
	strict,err:=guardedSeccompFile(true);if err!=nil{t.Fatal(err)};defer strict.Close()
	cfg:=LinuxEnforcerConfig{ProtectAll:true,BlockedIPv4:[]uint32{3,1,3},BlockedIPv6:[][16]byte{{3},{1},{3}}}
	digest:=func(c LinuxEnforcerConfig,uid,gid uint32,source string,fs []string,filter *os.File)string{
		t.Helper();d,err:=guardedPolicyDigest(c,uid,gid,source,fs,filter);if err!=nil{t.Fatal(err)};return d
	}
	base:=digest(cfg,42,43,"local_env",nil,f)
	reordered:=LinuxEnforcerConfig{ProtectAll:true,BlockedIPv4:[]uint32{1,3},BlockedIPv6:[][16]byte{{1},{3}}}
	if got:=digest(reordered,42,43,"local_env",[]string{},f);got!=base{t.Fatal("equivalent policy digest changed")}
	changed:=reordered;changed.BlockedIPv4=[]uint32{1,4}
	proxy:=reordered;proxy.Proxy=LinuxProxyConfig{IPv4:1,Port:2,Enabled:1}
	allowed:=reordered;allowed.AllowedTCP=[][20]byte{{1}}
	profile:=reordered;profile.TCPOnly=true
	for _,got:=range []string{
		digest(changed,42,43,"local_env",nil,f),
		digest(proxy,42,43,"local_env",nil,f),
		digest(allowed,42,43,"local_env",nil,f),
		digest(profile,42,43,"local_env",nil,f),
		digest(reordered,44,43,"local_env",nil,f),
		digest(reordered,42,44,"local_env",nil,f),
		digest(reordered,42,43,"control_plane",nil,f),
		digest(reordered,42,43,"local_env",[]string{"--landlock-access","fs:read-file"},f),
		digest(reordered,42,43,"local_env",nil,strict),
	}{if got==base{t.Fatal("changed policy input did not change digest")}}
	if pos,err:=f.Seek(0,1);err!=nil||pos!=0{t.Fatalf("digest moved filter read offset: %d %v",pos,err)}
	for _,bad:=range []string{"","sha256:no",strings.ToUpper(base),"sha256:"+strings.Repeat("0",64)}{
		t.Setenv(guardedExpectedDigestEnv,bad)
		if err:=verifyGuardedPolicyDigest(base);err==nil{t.Fatalf("bad expected digest accepted: %s",bad)}
	}
	t.Setenv(guardedExpectedDigestEnv,base)
	if err:=verifyGuardedPolicyDigest(base);err!=nil{t.Fatal(err)}
	for _,v:=range guardedWorkloadEnvironment([]string{guardedExpectedDigestEnv+"="+base,"PATH=/bin"}){
		if strings.HasPrefix(v,guardedExpectedDigestEnv+"="){t.Fatal("expected digest leaked to payload")}
	}
}

func TestGuardedProvenanceProbe(t *testing.T){
	if os.Getenv("GAVEL_PROVENANCE_PROBE")!="1"{t.Skip("guarded provenance probe")}
	if os.Getenv(guardedExpectedDigestEnv)!=""{t.Fatal("host digest leaked")}
	if os.Geteuid()!=421342{t.Fatal("unexpected UID")}
	if err:=os.WriteFile(os.Getenv("GAVEL_PROVENANCE_MARKER"),[]byte("ran"),0600);err!=nil{t.Fatal(err)}
}

func TestKernelGuardedPolicyProvenance(t *testing.T){
	if os.Getenv("GAVEL_RUN_KERNEL_TESTS")!="1"{t.Skip("requires isolated privileged VM")}
	if os.Geteuid()!=0{t.Fatal("requires root")}
	dir,err:=os.MkdirTemp("/tmp","gavel-provenance-");if err!=nil{t.Fatal(err)};defer os.RemoveAll(dir)
	if err:=os.Chown(dir,421342,421342);err!=nil{t.Fatal(err)}
	marker:=filepath.Join(dir,"ran")
	t.Setenv("GAVEL_MACHINE_KEY","")
	t.Setenv("GAVEL_MONITORED_PIDS","")
	t.Setenv("GAVEL_BLOCKED_IPS","127.0.0.2")
	t.Setenv("GAVEL_BLOCKED_IPV6","")
	t.Setenv("GAVEL_PROXY_IPV4","")
	t.Setenv("GAVEL_PROXY_PORT","")
	t.Setenv("GAVEL_AGENT_UID","421342")
	t.Setenv("GAVEL_AGENT_GID","421342")
	t.Setenv("GAVEL_PROVENANCE_MARKER",marker)
	t.Setenv("GAVEL_PROVENANCE_PROBE","1")
	exe,err:=os.Executable();if err!=nil{t.Fatal(err)}
	argv:=[]string{exe,"-test.run=^TestGuardedProvenanceProbe$","-test.v"}
	ip,err:=parseIPv4("127.0.0.2");if err!=nil{t.Fatal(err)}
	filter,err:=guardedSeccompFile(false);if err!=nil{t.Fatal(err)};defer filter.Close()
	digest,err:=guardedPolicyDigest(LinuxEnforcerConfig{ProtectAll:true,BlockedIPv4:[]uint32{ip}},421342,421342,"local_env",nil,filter)
	if err!=nil{t.Fatal(err)}
	t.Setenv(guardedExpectedDigestEnv,"sha256:"+strings.Repeat("0",64))
	if err:=runGuardedAgent(argv);err==nil||!strings.Contains(err.Error(),"digest mismatch"){t.Fatalf("mismatched policy must refuse launch: %v",err)}
	if _,err:=os.Stat(marker);!os.IsNotExist(err){t.Fatalf("payload ran or marker error: %v",err)}
	t.Setenv(guardedExpectedDigestEnv,digest)
	var logs bytes.Buffer
	old:=log.Writer();log.SetOutput(&logs);defer log.SetOutput(old)
	if err:=runGuardedAgent(argv);err!=nil{t.Fatalf("matching digest launch: %v\n%s",err,logs.String())}
	if got,err:=os.ReadFile(marker);err!=nil||string(got)!="ran"{t.Fatalf("positive payload marker: %q %v",got,err)}
	if !strings.Contains(logs.String(),"guarded_policy_snapshot schema="+guardedPolicySchema+" digest="+digest+" cgroup="){
		t.Fatalf("missing matching snapshot receipt: %s",logs.String())
	}
	t.Logf("KERNEL PROOF: wrong digest refused before payload; matching digest launched under pinned policy: %s",digest)
}
