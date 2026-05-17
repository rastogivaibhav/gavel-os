//go:build linux

package main

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
)

type linuxEnforcerObjects struct {
	MonitoredPIDs        *ebpf.Map
	BlockedIPv4          *ebpf.Map
	ProxyConfig          *ebpf.Map
	GavelRedirectHandler *ebpf.Program
}

func ebpfProgramStatus() string {
	return "runtime-generated"
}

func attachEnforcer(cgroupPath string, config LinuxEnforcerConfig) (func(), error) {
	objects, err := loadLinuxEnforcerObjects()
	if err != nil {
		return func() {}, err
	}
	if err := configureLinuxEnforcer(objects, config); err != nil {
		_ = objects.Close()
		return func() {}, err
	}

	attachedLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: objects.GavelRedirectHandler,
	})
	if err != nil {
		_ = objects.Close()
		return func() {}, err
	}

	return func() {
		_ = attachedLink.Close()
		_ = objects.Close()
	}, nil
}

func loadLinuxEnforcerObjects() (*linuxEnforcerObjects, error) {
	spec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			"monitored_pids": {
				Type:       ebpf.Hash,
				KeySize:    4,
				ValueSize:  1,
				MaxEntries: 1024,
			},
			"blocked_ipv4": {
				Type:       ebpf.Hash,
				KeySize:    4,
				ValueSize:  1,
				MaxEntries: 1024,
			},
			"proxy_config": {
				Type:       ebpf.Array,
				KeySize:    4,
				ValueSize:  12,
				MaxEntries: 1,
			},
		},
		Programs: map[string]*ebpf.ProgramSpec{
			"gavel_redirect_handler": {
				Name:         "gavel_redirect_handler",
				Type:         ebpf.CGroupSockAddr,
				AttachType:   ebpf.AttachCGroupInet4Connect,
				License:      "GPL",
				Instructions: buildConnect4Instructions(),
			},
		},
	}

	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load linux enforcer collection: %w", err)
	}

	objects := &linuxEnforcerObjects{
		MonitoredPIDs:        collection.Maps["monitored_pids"],
		BlockedIPv4:          collection.Maps["blocked_ipv4"],
		ProxyConfig:          collection.Maps["proxy_config"],
		GavelRedirectHandler: collection.Programs["gavel_redirect_handler"],
	}
	if objects.GavelRedirectHandler == nil {
		collection.Close()
		return nil, fmt.Errorf("missing gavel_redirect_handler program")
	}
	return objects, nil
}

func (objects *linuxEnforcerObjects) Close() error {
	if objects.GavelRedirectHandler != nil {
		_ = objects.GavelRedirectHandler.Close()
	}
	if objects.ProxyConfig != nil {
		_ = objects.ProxyConfig.Close()
	}
	if objects.BlockedIPv4 != nil {
		_ = objects.BlockedIPv4.Close()
	}
	if objects.MonitoredPIDs != nil {
		_ = objects.MonitoredPIDs.Close()
	}
	return nil
}

func configureLinuxEnforcer(objects *linuxEnforcerObjects, config LinuxEnforcerConfig) error {
	for _, pid := range config.MonitoredPIDs {
		value := uint8(1)
		if err := objects.MonitoredPIDs.Put(pid, value); err != nil {
			return fmt.Errorf("configure monitored pid %d: %w", pid, err)
		}
	}
	for _, ip := range config.BlockedIPv4 {
		value := uint8(1)
		if err := objects.BlockedIPv4.Put(ip, value); err != nil {
			return fmt.Errorf("configure blocked ip %d: %w", ip, err)
		}
	}
	if config.Proxy.Enabled == 1 {
		key := uint32(0)
		if err := objects.ProxyConfig.Put(key, config.Proxy); err != nil {
			return fmt.Errorf("configure proxy redirect: %w", err)
		}
	}
	return nil
}

func buildConnect4Instructions() asm.Instructions {
	const (
		pidKeyOffset   = -8
		ipKeyOffset    = -16
		proxyKeyOffset = -24
		ctxUserIP4     = 4
		ctxUserPort    = 24
	)

	return asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.FnGetCurrentPidTgid.Call(),
		asm.RSh.Imm(asm.R0, 32),
		asm.StoreMem(asm.RFP, pidKeyOffset, asm.R0, asm.Word),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, pidKeyOffset),
		asm.LoadMapPtr(asm.R1, 0).WithReference("monitored_pids"),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "allow"),
		asm.LoadMem(asm.R1, asm.R0, 0, asm.Byte),
		asm.JEq.Imm(asm.R1, 0, "allow"),

		asm.LoadMem(asm.R1, asm.R6, ctxUserIP4, asm.Word),
		asm.StoreMem(asm.RFP, ipKeyOffset, asm.R1, asm.Word),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, ipKeyOffset),
		asm.LoadMapPtr(asm.R1, 0).WithReference("blocked_ipv4"),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "maybe_redirect"),
		asm.LoadMem(asm.R1, asm.R0, 0, asm.Byte),
		asm.JEq.Imm(asm.R1, 0, "maybe_redirect"),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("deny"),
		asm.Return(),

		asm.Mov.Imm(asm.R1, 0).WithSymbol("maybe_redirect"),
		asm.StoreMem(asm.RFP, proxyKeyOffset, asm.R1, asm.Word),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, proxyKeyOffset),
		asm.LoadMapPtr(asm.R1, 0).WithReference("proxy_config"),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "allow"),
		asm.LoadMem(asm.R1, asm.R0, 8, asm.Word),
		asm.JEq.Imm(asm.R1, 0, "allow"),
		asm.LoadMem(asm.R1, asm.R0, 0, asm.Word),
		asm.StoreMem(asm.R6, ctxUserIP4, asm.R1, asm.Word),
		asm.LoadMem(asm.R1, asm.R0, 4, asm.Word),
		asm.StoreMem(asm.R6, ctxUserPort, asm.R1, asm.Word),

		asm.Mov.Imm(asm.R0, 1).WithSymbol("allow"),
		asm.Return(),
	}
}
