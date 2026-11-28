//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const guardedBootRequiredEnv = "GAVEL_REQUIRE_BOOT_INIT"
const guardedBootMarker = "boot-ready.json"

var bootIDPattern = regexp.MustCompile("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

type guardedBootIdentity struct {
	Version int
	BootID string
	Parent string
	Device uint64
	Inode uint64
}

func guardedBootRoot() error {
	if os.Geteuid() != 0 { return fmt.Errorf("boot gate requires privileged host operator") }
	if err := os.Mkdir(guardedLifecycleRoot,0700); err != nil && !errors.Is(err,os.ErrExist) { return err }
	if err := validateTrustedDirectoryChain(guardedLifecycleRoot); err != nil { return err }
	info, err := os.Lstat(guardedLifecycleRoot)
	if err != nil { return err }
	if info.Mode().Perm() != 0700 { return fmt.Errorf("boot state directory must be mode 0700") }
	return nil
}

// All guarded launches share this lock for their lifetime; boot initialization
// takes it exclusively. Never unlink the inode while operators can run.
func acquireGuardedBootLease(exclusive bool) (*os.File,error) {
	if err := guardedBootRoot(); err != nil { return nil,err }
	path := filepath.Join(guardedLifecycleRoot,"boot.lock")
	fd,err := unix.Open(path,unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK,0600)
	if err != nil { return nil,err }
	f := os.NewFile(uintptr(fd),"guarded-boot-lease")
	success := false
	defer func(){if !success{f.Close()}}()
	var st unix.Stat_t
	if err := unix.Fstat(fd,&st); err != nil { return nil,err }
	if st.Uid!=0 || st.Nlink!=1 || st.Mode&unix.S_IFMT!=unix.S_IFREG || st.Mode&0777!=0600 { return nil,fmt.Errorf("invalid boot lease inode") }
	mode:=unix.LOCK_SH
	if exclusive {mode=unix.LOCK_EX}
	if err:=unix.Flock(fd,mode|unix.LOCK_NB);err!=nil{return nil,fmt.Errorf("boot lifecycle lease unavailable: %w",err)}
	success=true
	return f,nil
}

func currentGuardedBootIdentity(parent string)(guardedBootIdentity,error){
	var id guardedBootIdentity
	var fs unix.Statfs_t
	if err:=unix.Statfs("/proc",&fs);err!=nil{return id,err}
	if fs.Type!=unix.PROC_SUPER_MAGIC{return id,fmt.Errorf("host procfs required")}
	raw,err:=os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err!=nil{return id,err}
	bootID:=strings.TrimSpace(string(raw))
	if !bootIDPattern.MatchString(bootID){return id,fmt.Errorf("invalid kernel boot identity")}
	if err:=validateGuardedCgroup(parent);err!=nil{return id,err}
	info,err:=os.Stat(parent);if err!=nil{return id,err}
	st,ok:=info.Sys().(*syscall.Stat_t)
	if !ok||st.Ino==0{return id,fmt.Errorf("cannot identify boot cgroup parent")}
	return guardedBootIdentity{1,bootID,parent,uint64(st.Dev),st.Ino},nil
}

func readGuardedBootMarker()(guardedBootIdentity,error){
	var id guardedBootIdentity
	path:=filepath.Join(guardedLifecycleRoot,guardedBootMarker)
	info,err:=os.Lstat(path);if err!=nil{return id,err}
	st,ok:=info.Sys().(*syscall.Stat_t)
	if !ok||st.Uid!=0||st.Nlink!=1||!info.Mode().IsRegular()||info.Mode().Perm()!=0600||info.Size()>4096{return id,fmt.Errorf("invalid boot readiness inode")}
	raw,err:=os.ReadFile(path);if err!=nil{return id,err}
	if err:=json.Unmarshal(raw,&id);err!=nil{return id,err}
	return id,nil
}

func writeGuardedBootMarker(id guardedBootIdentity)error{
	raw,err:=json.Marshal(id);if err!=nil{return err}
	f,err:=os.CreateTemp(guardedLifecycleRoot,".boot-ready-");if err!=nil{return err}
	defer os.Remove(f.Name());defer f.Close()
	if _,err:=f.Write(raw);err!=nil{return err}
	if err:=f.Sync();err!=nil{return err}
	if err:=f.Close();err!=nil{return err}
	if err:=os.Rename(f.Name(),filepath.Join(guardedLifecycleRoot,guardedBootMarker));err!=nil{return err}
	return syncRecoveryDirectory()
}

func requireGuardedBootReady(parent string)error{
	if err:=prepareGuardedPinRoot();err!=nil{return err}
	current,err:=currentGuardedBootIdentity(parent);if err!=nil{return err}
	marker,err:=readGuardedBootMarker();if err!=nil{return fmt.Errorf("boot readiness unavailable: %w",err)}
	if marker!=current{return fmt.Errorf("boot readiness identity mismatch")}
	return nil
}

// Run only under trusted boot/startup ordering. A failed initialization
// invalidates readiness. It never kills an unattributed cgroup by name.
func initializeGuardedBoot()error{
	lease,err:=acquireGuardedBootLease(true);if err!=nil{return err};defer lease.Close()
	marker:=filepath.Join(guardedLifecycleRoot,guardedBootMarker)
	if err:=os.Remove(marker);err!=nil&&!os.IsNotExist(err){return err}
	if err:=syncRecoveryDirectory();err!=nil{return err}
	parent,ok:=resolveLinuxCgroupPath();if !ok{return fmt.Errorf("cannot resolve boot cgroup parent")}
	id,err:=currentGuardedBootIdentity(parent);if err!=nil{return err}
	result,err:=sweepGuardedOrphans();if err!=nil{return err}
	if len(result.Busy)!=0{return fmt.Errorf("boot recovery has busy candidates: %v",result.Busy)}
	entries,err:=os.ReadDir(parent);if err!=nil{return err}
	for _,entry:=range entries{
		if guardedCgroupName.MatchString(entry.Name()){return fmt.Errorf("unresolved guarded cgroup at boot: %s",entry.Name())}
	}
	// No cooperating launch can race this publication under the exclusive lock.
	if err:=writeGuardedBootMarker(id);err!=nil{
		_ = os.Remove(marker)
		return err
	}
	return nil
}
