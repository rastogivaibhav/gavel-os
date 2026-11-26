//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const guardedLifecycleRoot = "/run/gavel-guarded-lifecycle"

// Never unlink these lock files while the service can be running: a new
// inode at the same path would permit two simultaneous holders. The host
// and its /run mount are trusted and shared by all cooperating operators.
func acquireGuardedLifecycleLease(name string) (*os.File,error) {
	if !guardedCgroupName.MatchString(name) {
		return nil,fmt.Errorf("invalid guarded lifecycle name %q",name)
	}
	if os.Geteuid()!=0 {
		return nil,fmt.Errorf("guarded lifecycle requires privileged host operator")
	}
	if err:=os.Mkdir(guardedLifecycleRoot,0700);err!=nil&&!errors.Is(err,os.ErrExist){return nil,err}
	if err:=validateTrustedDirectoryChain(guardedLifecycleRoot);err!=nil{return nil,err}
	info,err:=os.Lstat(guardedLifecycleRoot)
	if err!=nil{return nil,err}
	if info.Mode().Perm()!=0700{return nil,fmt.Errorf("lifecycle lease directory must be mode 0700")}
	path:=filepath.Join(guardedLifecycleRoot,name+".lock")
	fd,err:=unix.Open(path,unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK,0600)
	if err!=nil{return nil,err}
	f:=os.NewFile(uintptr(fd),"guarded-lifecycle-lease")
	ok:=false
	defer func(){if !ok{f.Close()}}()
	var st unix.Stat_t
	if err:=unix.Fstat(fd,&st);err!=nil{return nil,err}
	if st.Uid!=0||st.Mode&unix.S_IFMT!=unix.S_IFREG||st.Mode&0777!=0600||st.Nlink!=1{
		return nil,fmt.Errorf("invalid guarded lifecycle lease inode")
	}
	if err:=unix.Flock(fd,unix.LOCK_EX|unix.LOCK_NB);err!=nil{
		return nil,fmt.Errorf("lifecycle lease unavailable for %s: %w",name,err)
	}
	ok=true
	return f,nil
}
