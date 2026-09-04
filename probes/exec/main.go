// Probe "exec": starting a child process and reading its output. This is the path that
// uses the ProcThreadAttributeList functions, which XP does not have, and the pipe
// handling that ends in CancelIoEx.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	_ "github.com/unxed/go2xp/shim"
)

func main() {
	out, err := exec.Command("cmd", "/c", "echo go2xp").Output()
	if err != nil {
		fail("Output: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != "go2xp" {
		fail("child printed %q, want go2xp", got)
	}

	cmd := exec.Command("cmd", "/c", "exit 3")
	err = cmd.Run()
	var ee *exec.ExitError
	if !asExitError(err, &ee) || ee.ExitCode() != 3 {
		fail("exit code: got %v", err)
	}
	fmt.Println("OK exec")
}

func asExitError(err error, target **exec.ExitError) bool {
	e, ok := err.(*exec.ExitError)
	if ok {
		*target = e
	}
	return ok
}

func fail(format string, a ...any) {
	fmt.Printf("FAIL exec: "+format+"\n", a...)
	os.Exit(1)
}
