//go:build linux

package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/cilium/ebpf/asm"
)

const guardedNetProfileEnv = "GAVEL_AGENT_NET_PROFILE"
const guardedTCPAllowEnv = "GAVEL_AGENT_TCP_ALLOW"

func parseGuardedTCPAllow(raw string) ([][20]byte,error) {
	var entries []string
	if err:=json.Unmarshal([]byte(raw),&entries);err!=nil||entries==nil {
		return nil,fmt.Errorf("expected JSON array of literal IP:port endpoints")
	}
	if len(entries)>1024{return nil,fmt.Errorf("too many TCP endpoints")}
	keys:=make([][20]byte,0,len(entries))
	seen:=map[[20]byte]bool{}
	for _,entry:=range entries{
		a,err:=netip.ParseAddrPort(entry)
		if err!=nil||a.Port()==0||a.Addr().Zone()!=""||a.Addr().IsUnspecified()||a.Addr().IsMulticast(){
			return nil,fmt.Errorf("invalid TCP endpoint %q",entry)
		}
		ip:=a.Addr().Unmap().As16()
		var key [20]byte
		copy(key[:16],ip[:])
		binary.BigEndian.PutUint16(key[16:18],a.Port())
		if !seen[key]{keys=append(keys,key);seen[key]=true}
	}
	return keys,nil
}

func configureGuardedTCPProfile(config *LinuxEnforcerConfig)error{
	profile:=os.Getenv(guardedNetProfileEnv)
	raw,set:=os.LookupEnv(guardedTCPAllowEnv)
	if profile==""{
		if set{return fmt.Errorf("TCP allowlist requires tcp-services profile")}
		return nil
	}
	if profile!="tcp-services"{return fmt.Errorf("unknown network profile %q",profile)}
	if !config.ProtectAll||strings.TrimSpace(os.Getenv("GAVEL_MACHINE_KEY"))!=""||len(config.BlockedIPv4)>0||len(config.BlockedIPv6)>0||config.Proxy.Enabled!=0{
		return fmt.Errorf("TCP service profile requires local guarded mode without legacy block/redirect policy")
	}
	if !set{return fmt.Errorf("TCP service profile requires explicit %s",guardedTCPAllowEnv)}
	keys,err:=parseGuardedTCPAllow(raw);if err!=nil{return err}
	config.TCPOnly=true
	config.AllowedTCP=keys
	return nil
}

// bpf_sock_addr IPv4 offset 4, IPv6 offsets 8..20, port offset 24.
// The canonical key is 16 address bytes plus the 32-bit user_port field;
// IPv4 addresses use the standard ::ffff/96 prefix. Supported ABIs are LE.
func buildTCPServiceInstructions(v6 bool) asm.Instructions{
	const off int16=-32
	p:=asm.Instructions{asm.Mov.Reg(asm.R6,asm.R1)}
	if v6 {
		for i:=int16(0);i<16;i+=4{
			p=append(p,asm.LoadMem(asm.R1,asm.R6,8+i,asm.Word),asm.StoreMem(asm.RFP,off+i,asm.R1,asm.Word))
		}
	}else{
		p=append(p,asm.StoreImm(asm.RFP,off,0,asm.Word),asm.StoreImm(asm.RFP,off+4,0,asm.Word),
			asm.StoreImm(asm.RFP,off+8,0xffff0000,asm.Word),
			asm.LoadMem(asm.R1,asm.R6,4,asm.Word),asm.StoreMem(asm.RFP,off+12,asm.R1,asm.Word))
	}
	return append(p,asm.LoadMem(asm.R1,asm.R6,24,asm.Word),asm.StoreMem(asm.RFP,off+16,asm.R1,asm.Word),
		asm.Mov.Reg(asm.R2,asm.RFP),asm.Add.Imm(asm.R2,int32(off)),
		asm.LoadMapPtr(asm.R1,0).WithReference("allowed_tcp"),asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0,0,"deny_service"),asm.LoadMem(asm.R1,asm.R0,0,asm.Byte),
		asm.JEq.Imm(asm.R1,0,"deny_service"),asm.Mov.Imm(asm.R0,1),asm.Return(),
		asm.Mov.Imm(asm.R0,0).WithSymbol("deny_service"),asm.Return())
}
