// Probe "signals": console control events reaching os/signal.
//
// The event is not sent to our own process group, which would take the test harness down
// with it. Instead the probe re-executes itself in a new process group, sends
// CTRL_BREAK_EVENT to that group alone and checks that the child's os/signal machinery
// woke up and exited cleanly. This is also the shape f4 needs: run a child, then be able
// to interrupt it without killing yourself.
//go:build windows

package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	_ "github.com/unxed/go2xp/shim"
)

const (
	createNewProcessGroup = 0x00000200
	ctrlBreakEvent        = 1
)

var procGenerateConsoleCtrlEvent = syscall.NewLazyDLL("kernel32.dll").NewProc("GenerateConsoleCtrlEvent")

// onWine reports whether we are running under Wine, which exports a version function
// from ntdll that no real Windows has.
func onWine() bool {
	return syscall.NewLazyDLL("ntdll.dll").NewProc("wine_get_version").Find() == nil
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-child" {
		child()
		return
	}

	exe, err := os.Executable()
	if err != nil {
		fail("Executable: %v", err)
	}
	cmd := exec.Command(exe, "-child")
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNewProcessGroup}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fail("StdoutPipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		fail("Start: %v", err)
	}

	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "ready" {
		cmd.Process.Kill()
		fail("child never became ready (%q, %v)", line, err)
	}

	r, _, e := procGenerateConsoleCtrlEvent.Call(ctrlBreakEvent, uintptr(cmd.Process.Pid))
	if r == 0 {
		cmd.Process.Kill()
		// Without a console there is no one to deliver the event to; that is a property
		// of the environment, not of the shim.
		fmt.Printf("SKIP signals: GenerateConsoleCtrlEvent: %v\n", e)
		return
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			fail("child exited with %v, want success", err)
		}
	case <-time.After(30 * time.Second):
		cmd.Process.Kill()
		if onWine() {
			// Wine's GenerateConsoleCtrlEvent reports success but does not deliver the
			// event to another process group. Nothing in the shim is involved in the
			// delivery path, so this only means the probe needs real Windows to be
			// conclusive.
			fmt.Println("SKIP signals: Wine does not deliver control events across process groups")
			return
		}
		fail("child ignored CTRL_BREAK")
	}
	fmt.Println("OK signals")
}

func child() {
	c := make(chan os.Signal, 1)
	// SIGBREAK is what os/signal reports for CTRL_BREAK_EVENT on Windows. The syscall
	// package does not name it, so use its value directly.
	signal.Notify(c, os.Interrupt, syscall.Signal(21))
	fmt.Println("ready")
	select {
	case <-c:
		os.Exit(0)
	case <-time.After(30 * time.Second):
		os.Exit(1)
	}
}

func fail(format string, a ...any) {
	fmt.Printf("FAIL signals: "+format+"\n", a...)
	os.Exit(1)
}
