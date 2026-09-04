// Probe "hello": the smallest program that still touches the parts of the runtime
// most likely to break on XP - the scheduler, timers and the OS entropy source.
// It prints "OK hello" and exits 0; on failure it prints the error and exits 1.
// Output also goes to hello.log next to the exe, because a console window on XP
// may close before it can be read.
package main

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/unxed/go2xp/shim"
)

func main() {
	var log *os.File
	if exe, err := os.Executable(); err == nil {
		log, _ = os.Create(filepath.Join(filepath.Dir(exe), "hello.log"))
		defer log.Close()
	}
	say := func(format string, a ...any) {
		fmt.Printf(format+"\n", a...)
		if log != nil {
			fmt.Fprintf(log, format+"\n", a...)
		}
	}

	// A goroutine plus a channel exercises the scheduler and the timer path.
	done := make(chan struct{})
	go func() {
		time.Sleep(10 * time.Millisecond)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		say("FAIL hello: goroutine did not finish in 5s")
		os.Exit(1)
	}

	// crypto/rand reaches ProcessPrng on Windows, which XP does not have.
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		say("FAIL hello: crypto/rand: %v", err)
		os.Exit(1)
	}

	say("OK hello (runtime %s, %d random bytes: %x)", time.Now().Format("15:04:05"), len(buf), buf[:4])
}
