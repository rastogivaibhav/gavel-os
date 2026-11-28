//go:build linux

package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"strings"
)

const guardedPolicySchema = "gavel-guarded-policy-v1"
const guardedExpectedDigestEnv = "GAVEL_AGENT_EXPECTED_POLICY_DIGEST"

// This is a versioned digest of the effective launch configuration, not
// attestation of the kernel, executable, mounted filesystem or trusted host.
// No agent arguments, machine key or raw policy are emitted by the launcher.
type guardedPolicySnapshot struct {
	Schema string
	Arch string
	Source string
	UID uint32
	GID uint32
	ProtectAll bool
	TCPOnly bool
	BlockedIPv4 []uint32
	BlockedIPv6 []string
	AllowedTCP []string
	Proxy LinuxProxyConfig
	LandlockArgs []string
	SeccompSHA256 string
}

func guardedPolicyDigest(config LinuxEnforcerConfig, uid,gid uint32, source string, fsArgs []string, filter *os.File)(string,error){
	if filter==nil || !config.ProtectAll || len(config.MonitoredPIDs)!=0 {
		return "",fmt.Errorf("expected resolved guarded configuration and sealed filter")
	}
	if source!="local_env" && source!="control_plane" {return "",fmt.Errorf("invalid policy source")}
	info,err:=filter.Stat();if err!=nil{return "",err}
	if info.Size()<=0||info.Size()>4096*8{return "",fmt.Errorf("invalid filter length")}
	// The file is the exact sealed object later passed to setpriv. SectionReader
	// uses ReadAt, so digesting it cannot advance the launcher read offset.
	hash:=sha256.New()
	if _,err:=io.Copy(hash,io.NewSectionReader(filter,0,info.Size()));err!=nil{return "",err}
	ip4:=append([]uint32{},config.BlockedIPv4...)
	slices.Sort(ip4)
	ip4=slices.Compact(ip4)
	ip6:=make([]string,0,len(config.BlockedIPv6))
	for _,key:=range config.BlockedIPv6{ip6=append(ip6,hex.EncodeToString(key[:]))}
	slices.Sort(ip6)
	ip6=slices.Compact(ip6)
	tcp:=make([]string,0,len(config.AllowedTCP))
	for _,key:=range config.AllowedTCP{tcp=append(tcp,hex.EncodeToString(key[:]))}
	slices.Sort(tcp)
	tcp=slices.Compact(tcp)
	snapshot:=guardedPolicySnapshot{
		Schema:guardedPolicySchema,Arch:runtime.GOARCH,Source:source,UID:uid,GID:gid,
		ProtectAll:config.ProtectAll,TCPOnly:config.TCPOnly,BlockedIPv4:ip4,BlockedIPv6:ip6,AllowedTCP:tcp,
		Proxy:config.Proxy,LandlockArgs:append([]string{},fsArgs...),SeccompSHA256:hex.EncodeToString(hash.Sum(nil)),
	}
	raw,err:=json.Marshal(snapshot);if err!=nil{return "",err}
	sum:=sha256.Sum256(raw)
	return "sha256:"+hex.EncodeToString(sum[:]),nil
}

func verifyGuardedPolicyDigest(actual string)error{
	expected,set:=os.LookupEnv(guardedExpectedDigestEnv)
	if !set{return nil}
	return verifyGuardedApprovedDigest(expected, actual)
}

func verifyGuardedApprovedDigest(expected, actual string) error {
	if len(expected)!=71||!strings.HasPrefix(expected,"sha256:")||expected!=strings.ToLower(expected){
		return fmt.Errorf("expected policy digest must be sha256: followed by 64 lowercase hex digits")
	}
	if _,err:=hex.DecodeString(expected[7:]);err!=nil{return fmt.Errorf("malformed expected policy digest")}
	if subtle.ConstantTimeCompare([]byte(expected),[]byte(actual))!=1{
		return fmt.Errorf("expected policy digest mismatch (resolved %s)",actual)
	}
	return nil
}
