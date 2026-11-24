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
)

func TestGuardedFilesystemPolicyValidation(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir,"bin")
	if err := os.Mkdir(bin,0755); err != nil { t.Fatal(err) }
	work := filepath.Join(dir,"work")
	if err := os.Mkdir(work,0755); err != nil { t.Fatal(err) }
	for _, raw := range []string{"", "{}", "null", "{\"execute\":[\"/\"]}", "{\"execute\":[\"relative\"]}", "{\"execute\":[\"/does-not-exist-gavel\"]}", "{\"bogus\":[]}", "{\"execute\":[\"/bin/true\"]} {}"} {
		if _,err := compileGuardedFilesystemPolicy(raw); err == nil { t.Fatalf("accepted invalid policy %q",raw) }
	}
	raw,_ := json.Marshal(guardedFilesystemPolicy{Read:[]string{work},Write:[]string{work},Execute:[]string{bin}})
	args,err := compileGuardedFilesystemPolicy(string(raw))
	if err != nil { t.Fatal(err) }
	if !strings.Contains(strings.Join(args," "),"truncate") { t.Fatal("truncate missing") }
	raw,_ = json.Marshal(guardedFilesystemPolicy{Write:[]string{dir},Execute:[]string{bin}})
	if _,err := compileGuardedFilesystemPolicy(string(raw)); err == nil { t.Fatal("writable executable hierarchy accepted") }
	t.Setenv(guardedFilesystemEnv,string(raw))
	if _,err := guardedFilesystemArguments(); err == nil { t.Fatal("invalid configured policy must fail closed") }
}

func TestGuardedFilesystemProbe(t *testing.T) {
	mode := os.Getenv("GAVEL_FS_TEST_MODE")
	if mode == "" { t.Skip("isolated filesystem probe") }
	root := os.Getenv("GAVEL_FS_TEST_ROOT")
	secret := filepath.Join(root,"private","secret")
	config := filepath.Join(root,"private","config")
	allowed := filepath.Join(root,"work","allowed")
	deniedExe := filepath.Join(root,"private","denied-exe")
	allowedExe := filepath.Join(root,"bin","allowed-exe")
	if mode == "control" {
		if _,err := os.ReadFile(secret); err != nil { t.Fatal(err) }
		f,err := os.OpenFile(config,os.O_WRONLY,0)
		if err != nil { t.Fatal(err) }; f.Close()
		if err := exec.Command(deniedExe).Run(); err != nil { t.Fatal(err) }
		return
	}
	deny := func(name string,err error) {
		t.Helper()
		if !errors.Is(err,syscall.EACCES) && !errors.Is(err,syscall.EPERM) && !errors.Is(err,syscall.EXDEV) {
			t.Fatalf("%s: expected kernel denial, got %v",name,err)
		}
	}
	if os.Getenv(guardedFilesystemEnv) != "" { t.Fatal("host policy leaked into payload") }
	if data,err := os.ReadFile(allowed); err != nil || string(data)!="allowed" { t.Fatalf("allowed read: %q %v",data,err) }
	if err := os.WriteFile(filepath.Join(root,"work","new"),[]byte("permitted"),0600); err != nil { t.Fatal(err) }
	if err := exec.Command(allowedExe).Run(); err != nil { t.Fatalf("allowed exec: %v",err) }
	_,err := os.ReadFile(secret); deny("secret read",err)
	f,err := os.OpenFile(config,os.O_WRONLY|os.O_TRUNC,0); if f!=nil { f.Close() }; deny("config write",err)
	deny("config truncate",os.Truncate(config,0))
	deny("config remove",os.Remove(config))
	deny("config rename",os.Rename(config,filepath.Join(root,"work","moved")))
	deny("unauthorized execute",exec.Command(deniedExe).Run())
	if mode == "guarded" {
		exe,err := os.Executable(); if err != nil { t.Fatal(err) }
		cmd := exec.Command(exe,"-test.run=^TestGuardedFilesystemProbe$","-test.v")
		cmd.Env = append(os.Environ(),"GAVEL_FS_TEST_MODE=descendant")
		out,err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(out),"PASS: TestGuardedFilesystemProbe") { t.Fatalf("descendant proof: %v %s",err,out) }
	}
	t.Log("KERNEL PROOF: allowed read/write/exec; forbidden read/write/truncate/remove/rename/exec denied")
}

func TestKernelGuardedFilesystem(t *testing.T) {
	if os.Getenv("GAVEL_RUN_KERNEL_TESTS")!="1" { t.Skip("requires isolated privileged Linux VM") }
	if os.Geteuid()!=0 { t.Fatal("requires root") }
	root,err := os.MkdirTemp("/tmp","gavel-fs-proof-")
	if err != nil { t.Fatal(err) }; defer os.RemoveAll(root)
	if err := os.Chmod(root,0755); err != nil { t.Fatal(err) }
	for _,sub := range []string{"private","work","bin"} {
		path := filepath.Join(root,sub)
		if err := os.Mkdir(path,0777); err != nil { t.Fatal(err) }
		if err := os.Chmod(path,0777); err != nil { t.Fatal(err) }
	}
	for _,item := range []struct{path,data string}{{"private/secret","synthetic-secret"},{"private/config","original"},{"work/allowed","allowed"}} {
		path:=filepath.Join(root,item.path)
		if err:=os.WriteFile(path,[]byte(item.data),0666); err!=nil { t.Fatal(err) }
		if err:=os.Chmod(path,0666); err!=nil { t.Fatal(err) }
	}
	data,err:=os.ReadFile("/usr/bin/true"); if err!=nil { t.Fatal(err) }
	for _,path:=range []string{"private/denied-exe","bin/allowed-exe"} {
		if err:=os.WriteFile(filepath.Join(root,path),data,0755); err!=nil { t.Fatal(err) }
	}
	exe,err:=os.Executable(); if err!=nil { t.Fatal(err) }
	t.Setenv("GAVEL_FS_TEST_ROOT",root)
	control:=exec.Command(exe,"-test.run=^TestGuardedFilesystemProbe$","-test.v")
	control.Env=append(os.Environ(),"GAVEL_FS_TEST_MODE=control")
	control.SysProcAttr=&syscall.SysProcAttr{Credential:&syscall.Credential{Uid:65534,Gid:65534}}
	if out,err:=control.CombinedOutput();err!=nil || !strings.Contains(string(out),"PASS: TestGuardedFilesystemProbe") { t.Fatalf("unguarded positive control: %v %s",err,out) }
	read:=[]string{filepath.Join(root,"work"),filepath.Join(root,"bin"),exe}
	execute:=[]string{filepath.Join(root,"bin"),exe}
	for _,path:=range []string{"/usr/lib","/lib","/lib64","/etc/ld.so.cache","/proc/self/exe"} {
		if _,err:=os.Stat(path);err!=nil { continue }
		// /proc/self/exe resolves differently at launch; the actual test
		// executable is already explicitly authorized.
		if path=="/proc/self/exe" { continue }
		read=append(read,path)
		if path!="/etc/ld.so.cache" { execute=append(execute,path) }
	}
	policy,err:=json.Marshal(guardedFilesystemPolicy{Read:read,Write:[]string{filepath.Join(root,"work")},Execute:execute})
	if err!=nil { t.Fatal(err) }
	t.Setenv(guardedFilesystemEnv,string(policy))
	t.Setenv("GAVEL_FS_TEST_MODE","guarded")
	t.Setenv("GAVEL_MACHINE_KEY","")
	t.Setenv("GAVEL_MONITORED_PIDS","")
	t.Setenv("GAVEL_BLOCKED_IPS","127.0.0.2")
	t.Setenv("GAVEL_AGENT_UID","65534")
	t.Setenv("GAVEL_AGENT_GID","65534")
	if err:=runGuardedAgent([]string{exe,"-test.run=^TestGuardedFilesystemProbe$","-test.v"});err!=nil { t.Fatal(err) }
	if got,err:=os.ReadFile(filepath.Join(root,"private","config"));err!=nil || string(got)!="original" { t.Fatalf("protected config changed: %q %v",got,err) }
	if got,err:=os.ReadFile(filepath.Join(root,"work","new"));err!=nil || string(got)!="permitted" { t.Fatalf("positive write missing: %q %v",got,err) }
}
