//go:build linux

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

const guardedFilesystemEnv = "GAVEL_AGENT_FS_POLICY"
const landlockHandledFS = "execute,write-file,read-file,read-dir,remove-dir,remove-file,make-char,make-dir,make-reg,make-sock,make-fifo,make-block,make-sym,refer,truncate"

type guardedFilesystemPolicy struct {
	Read []string `json:"read"`
	Write []string `json:"write"`
	Execute []string `json:"execute"`
}

// Compile the host-supplied allowlist. Paths must already exist; permissions
// refer to resolved filesystem objects and directory subtrees, not glob patterns.
func compileGuardedFilesystemPolicy(raw string) ([]string, error) {
	var policy guardedFilesystemPolicy
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&policy); err != nil { return nil, err }
	if err := dec.Decode(new(any)); err != io.EOF { return nil, fmt.Errorf("expected one JSON policy object") }
	if len(policy.Execute) == 0 { return nil, fmt.Errorf("at least one executable path must be allowed") }
	type rule struct { dir bool; rights map[string]bool }
	rules := map[string]rule{}
	for _, category := range []struct { paths []string; kind string }{
		{policy.Read, "read"}, {policy.Write, "write"}, {policy.Execute, "execute"},
	} {
		for _, path := range category.paths {
			if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || strings.ContainsAny(path, ":\n\r\x00") {
				return nil, fmt.Errorf("invalid policy path %q", path)
			}
			resolved, err := filepath.EvalSymlinks(path)
			if err != nil { return nil, err }
			if resolved == "/" || strings.ContainsAny(resolved, ":\n\r\x00") {
				return nil, fmt.Errorf("invalid resolved path %q", resolved)
			}
			info, err := os.Stat(resolved)
			if err != nil { return nil, err }
			if !info.IsDir() && !info.Mode().IsRegular() {
				return nil, fmt.Errorf("policy path must be regular file or directory: %s", resolved)
			}
			r, ok := rules[resolved]
			if !ok { r = rule{dir: info.IsDir(), rights: map[string]bool{}} }
			switch category.kind {
			case "read":
				r.rights["read-file"] = true
				if r.dir { r.rights["read-dir"] = true }
			case "write":
				r.rights["write-file"] = true
				r.rights["truncate"] = true
				if r.dir {
					for _, right := range []string{"remove-dir","remove-file","make-dir","make-reg","make-sym","refer"} { r.rights[right] = true }
				}
			case "execute":
				r.rights["execute"] = true
			}
			rules[resolved] = r
		}
	}
	// Avoid authorizing native execution directly from writable trees.
	// This does not stop an allowed interpreter from reading a script.
	overlap := func(a,b string) bool { return a == b || strings.HasPrefix(a,b+"/") || strings.HasPrefix(b,a+"/") }
	for a, ar := range rules {
		if !ar.rights["execute"] { continue }
		for b, br := range rules {
			if br.rights["write-file"] && overlap(a,b) {
				return nil, fmt.Errorf("write and execute rules overlap: %s and %s", a,b)
			}
		}
	}
	args := []string{"--landlock-access","fs:"+landlockHandledFS}
	paths := make([]string,0,len(rules))
	for path := range rules { paths = append(paths,path) }
	sort.Strings(paths)
	for _, path := range paths {
		rights := make([]string,0,len(rules[path].rights))
		for right := range rules[path].rights { rights = append(rights,right) }
		sort.Strings(rights)
		args = append(args,"--landlock-rule","path-beneath:"+strings.Join(rights,",")+":"+path)
	}
	return args,nil
}

func guardedFilesystemArguments() ([]string,error) {
	raw, configured := os.LookupEnv(guardedFilesystemEnv)
	if !configured { return nil,nil }
	args, err := compileGuardedFilesystemPolicy(raw)
	if err != nil { return nil,err }
	// ABI 3 introduced explicit truncate mediation. Never downgrade rights.
	abi, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, 1)
	if errno != 0 { return nil,fmt.Errorf("Landlock ABI query: %w",errno) }
	if abi < 3 { return nil,fmt.Errorf("Landlock ABI >= 3 required; found %d",abi) }
	return args,nil
}
