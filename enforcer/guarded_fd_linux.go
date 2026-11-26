//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"

	"golang.org/x/sys/unix"
)

// The guarded supervisor is a dedicated process. Mark its inherited and
// currently open descriptors close-on-exec, without closing resources needed
// by the supervisor. Linux >=5.11 is required; no unsafe fallback.
// Trusted supervisor threads must use atomic CLOEXEC for any new opens.
func sealAmbientDescriptors() error {
	return unix.CloseRange(3, uint(^uint32(0)), unix.CLOSE_RANGE_CLOEXEC)
}

// Preserve only write-only pipes and the actual /dev/null character device
// as output endpoints. Never inherit an arbitrary regular file, terminal,
// connected socket, or read/write endpoint. The host is responsible for the
// trusted consumer of an output pipe; this is not IPC broker authorization.
func validateGuardedOutput(f *os.File) error {
	if f == nil {
		return fmt.Errorf("missing output endpoint")
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return err
	}
	flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
	if err != nil { return err }
	if flags & unix.O_ACCMODE != unix.O_WRONLY {
		return fmt.Errorf("output must be write-only")
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFIFO:
		return nil
	case unix.S_IFCHR:
		if uint64(st.Rdev) == unix.Mkdev(1, 3) { return nil }
	}
	return fmt.Errorf("output must be a write-only pipe or /dev/null")
}

func configureGuardedDescriptors(cmd *exec.Cmd) error {
	if err := validateGuardedOutput(os.Stdout); err != nil {
		return fmt.Errorf("stdout: %w", err)
	}
	if err := validateGuardedOutput(os.Stderr); err != nil {
		return fmt.Errorf("stderr: %w", err)
	}
	// A nil stdin makes os/exec attach /dev/null, never supervisor input.
	cmd.Stdin = nil
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return nil
}
