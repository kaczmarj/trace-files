// trace-files lists all of the files used by a process and its offspring.
//
// With lots of help from:
//  - https://github.com/lizrice/strace-from-scratch
// 	- https://stackoverflow.com/q/5477976/5666087
// 	- https://stackoverflow.com/q/18502203/5666087

// +build linux

package main

import (
	"bufio"
	"fmt"
	"golang.org/x/sys/unix"
	"log"
	"os"
	"os/exec"
	"runtime"
	"sort"
)

func init() {
	runtime.LockOSThread()
}

func main() {
	var err error

	if len(os.Args) < 2 {
		log.Fatalf("usage: ./trace-files program [arg]...")
	}
	cmd := exec.Command(os.Args[1], os.Args[2:]...)
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.SysProcAttr = &unix.SysProcAttr{
		Ptrace: true,
	}
	if err = cmd.Start(); err != nil {
		log.Fatalf("error starting command: %s\n", err)
	}
	if err = cmd.Wait(); err != nil {
		// We expect "trace/breakpoint trap" here.
		fmt.Printf("Wait returned: %s\n", err)
	}

	pid := cmd.Process.Pid

	var regs unix.PtraceRegs
	var status unix.WaitStatus

	// TODO: Setting these options causes the multiprocessing Python script to hang.
	ptraceOptions := unix.PTRACE_O_TRACEVFORK | unix.PTRACE_O_TRACEFORK | unix.PTRACE_O_TRACECLONE
	if err = unix.PtraceSetOptions(pid, ptraceOptions); err != nil {
		log.Fatalf("error setting ptrace options: %s", err)
	}

	//fmt.Println("pid\tsyscall")

	exit := false

	filesCaught := make(stringSet)

	for {
		if exit {
			err = unix.PtraceGetRegs(pid, &regs)
			if err != nil {
				break
			}

			// TODO: document these syscall numbers! Or better, make them constants.
			// TODO: when should we grab files? See reprozip's implementation.
			if regs.Orig_rax == 59 || regs.Orig_rax == 2 || regs.Orig_rax == 85 || regs.Orig_rax == 257 {
				// Find the files used.
				thisSet, err := readProcMaps(pid)
				if err != nil {
					log.Fatalf("error reading procfile: %s", err)
				}
				filesCaught.update(thisSet)
			}

			//name, err := seccomp.ScmpSyscall(regs.Orig_rax).GetName()
			//if err != nil {
			//	fmt.Printf("error getting syscall name for orig_rax %d\n", regs.Orig_rax)
			//}
			//fmt.Printf("%d\t%s\n", pid, name)
		}
		// TODO: sometimes this error is thrown when testing a multiprocessing python script:
		// 		error calling ptrace syscall: no such process
		if err = unix.PtraceSyscall(pid, 0); err != nil {
			log.Fatalf("error calling ptrace syscall: %s\n", err)
		}

		// TODO: is it OK to overwrite pid here?
		pid, err = unix.Wait4(-1, &status, 0, nil)
		if err != nil {
			log.Fatalf("error calling wait")
		}
		exit = !exit
	}

	ff := filesCaught.toSlice()
	sort.Strings(ff)
	for i, f := range ff {
		fmt.Printf("%d\t%s\n", i, f)
	}
}

// procMapsLine represents one line in the file /proc/PID/maps.
// See https://man7.org/linux/man-pages/man5/proc.5.html for more information.
//
// Permission to access this file is governed by a ptrace access mode PTRACE_MODE_READ_FSCREDS check; see ptrace(2).
//
//    address           perms offset  dev   inode       pathname
//    00400000-00452000 r-xp 00000000 08:02 173521      /usr/bin/dbus-daemon
//    00651000-00652000 r--p 00051000 08:02 173521      /usr/bin/dbus-daemon
//    00652000-00655000 rw-p 00052000 08:02 173521      /usr/bin/dbus-daemon
//    00e03000-00e24000 rw-p 00000000 00:00 0           [heap]
//    00e24000-011f7000 rw-p 00000000 00:00 0           [heap]
type procMapsLine struct {
	addressStart int
	addressEnd   int
	perms        string
	offset       int
	deviceMajor  int
	deviceMinor  int
	inode        int
	pathname     string
}

// newProcMapsLineFromString creates a new procMapsLine from a string.
func newProcMapsLineFromString(str string) (*procMapsLine, error) {
	p := procMapsLine{}
	format := "%x-%x %4s %x %x:%x %x %s"
	n, _ := fmt.Sscanf(str, format, &p.addressStart, &p.addressEnd, &p.perms, &p.offset, &p.deviceMajor,
		&p.deviceMinor, &p.inode, &p.pathname)
	// Sometimes pathname is not present, so seven items are found.
	if n < 7 {
		return nil, fmt.Errorf("error parsing line of procfile: found fewer than seven items")
	}
	return &p, nil
}

// readProcMaps returns a set of the pathnames in `/proc/PID/maps` with inode > 0.
// With help from https://stackoverflow.com/a/16615559/5666087.
func readProcMaps(pid int) (*stringSet, error) {
	filepath := fmt.Sprintf("/proc/%d/maps", pid)
	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer func() {
		err := file.Close()
		if err != nil {
			fmt.Printf("error closing file: %s", filepath)
		}
	}()

	set := make(stringSet)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line, err := newProcMapsLineFromString(scanner.Text())
		if err != nil {
			return nil, err
		}
		if line.inode > 0 {
			set.add(line.pathname)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	return &set, nil
}

// stringSet is a set implementation for strings.
type stringSet map[string]struct{}

// add adds a string to the set.
func (set *stringSet) add(s string) {
	(*set)[s] = struct{}{}
}

// update adds the values of another set to this set.
func (set *stringSet) update(other *stringSet) {
	for k := range *other {
		set.add(k)
	}
}

// toSlice returns the strings in the set as a slice.
func (set *stringSet) toSlice() []string {
	keys := make([]string, len(*set))
	i := 0
	for k := range *set {
		keys[i] = k
		i++
	}
	return keys
}
