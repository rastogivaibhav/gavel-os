//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const guardedUIDLeaseRoot = "/run/gavel-guarded-uids"

func credentialUIDMatches(status string, uid uint32) (bool,error) {
	for _, line := range strings.Split(status,"\n") {
		if !strings.HasPrefix(line,"Uid:") {continue}
		fields:=strings.Fields(strings.TrimPrefix(line,"Uid:"))
		if len(fields)!=4{return false,fmt.Errorf("malformed task UID record")}
		match:=false
		for _,f:=range fields {
			n,err:=strconv.ParseUint(f,10,32)
			if err!=nil{return false,fmt.Errorf("malformed task UID: %w",err)}
			match=match||uint32(n)==uid
		}
		return match,nil
	}
	return false,fmt.Errorf("missing task UID record")
}

func requireUnusedGuardedUID(uid uint32) error {
	var fs unix.Statfs_t
	if err:=unix.Statfs("/proc",&fs);err!=nil{return err}
	if fs.Type!=unix.PROC_SUPER_MAGIC{return fmt.Errorf("host procfs required")}
	procs,err:=os.ReadDir("/proc")
	if err!=nil{return err}
	for _,p:=range procs {
		if _,err:=strconv.ParseUint(p.Name(),10,32);err!=nil{continue}
		taskDir:=filepath.Join("/proc",p.Name(),"task")
		tasks,err:=os.ReadDir(taskDir)
		if errors.Is(err,os.ErrNotExist){continue}
		if err!=nil{return fmt.Errorf("enumerate task credentials %s: %w",p.Name(),err)}
		for _,task:=range tasks {
			if _,err:=strconv.ParseUint(task.Name(),10,32);err!=nil{continue}
			path:=filepath.Join(taskDir,task.Name(),"status")
			data,err:=os.ReadFile(path)
			if errors.Is(err,os.ErrNotExist){continue}
			if err!=nil{return fmt.Errorf("inspect task credentials %s: %w",path,err)}
			match,err:=credentialUIDMatches(string(data),uid)
			if err!=nil{return fmt.Errorf("inspect task credentials %s: %w",path,err)}
			if match{return fmt.Errorf("UID %d already in use by host-visible task %s/%s",uid,p.Name(),task.Name())}
		}
	}
	return nil
}

func acquireGuardedUIDLease(uid uint32)(*os.File,error){
	if uid==0||uid==^uint32(0){return nil,fmt.Errorf("invalid dedicated UID")}
	if err:=os.Mkdir(guardedUIDLeaseRoot,0700);err!=nil&&!errors.Is(err,os.ErrExist){return nil,err}
	if err:=validateTrustedDirectoryChain(guardedUIDLeaseRoot);err!=nil{return nil,err}
	info,err:=os.Lstat(guardedUIDLeaseRoot)
	if err!=nil{return nil,err}
	if info.Mode().Perm()!=0700{return nil,fmt.Errorf("UID lease directory must be mode 0700")}
	path:=filepath.Join(guardedUIDLeaseRoot,strconv.FormatUint(uint64(uid),10)+".lock")
	fd,err:=unix.Open(path,unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC,0600)
	if err!=nil{return nil,err}
	f:=os.NewFile(uintptr(fd),"guarded-uid-lease")
	ok:=false
	defer func(){if !ok{f.Close()}}()
	var st unix.Stat_t
	if err:=unix.Fstat(fd,&st);err!=nil{return nil,err}
	if st.Uid!=0||st.Mode&unix.S_IFMT!=unix.S_IFREG||st.Mode&0777!=0600||st.Nlink!=1{return nil,fmt.Errorf("invalid UID lease inode")}
	if err:=unix.Flock(fd,unix.LOCK_EX|unix.LOCK_NB);err!=nil{return nil,fmt.Errorf("UID %d lease unavailable: %w",uid,err)}
	if err:=requireUnusedGuardedUID(uid);err!=nil{return nil,err}
	ok=true
	return f,nil
}
