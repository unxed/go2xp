// Probe "net": sockets through the Go netpoller - the code path that creates sockets
// with WSASocketW, drives them through the I/O completion port (and therefore through
// the GetQueuedCompletionStatusEx emulation) and resolves names with GetAddrInfoW.
//
// The first two checks are local and need no network. The external HTTP checks are
// attempted but reported as SKIP when there is no connectivity, so the probe stays
// meaningful on an air-gapped VM.
package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	_ "github.com/unxed/go2xp/shim"
)

func main() {
	// 1. Listen, connect and exchange bytes over loopback.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	check(err, "Listen")
	defer ln.Close()

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.Copy(c, c) // echo
	}()

	c, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	check(err, "Dial")
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("go2xp")); err != nil {
		fail("Write: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil {
		fail("Read: %v", err)
	}
	c.Close()
	if string(buf) != "go2xp" {
		fail("echo returned %q", buf)
	}

	// 2. A local HTTP server, which layers net/http and its goroutine-per-connection
	//    model on top of the same netpoller.
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "ok")
	})}
	hl, err := net.Listen("tcp", "127.0.0.1:0")
	check(err, "Listen http")
	go srv.Serve(hl)
	defer srv.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	body, err := get(client, "http://"+hl.Addr().String()+"/")
	check(err, "local GET")
	if body != "ok" {
		fail("local GET returned %q", body)
	}

	// 3. Name resolution and an external connection, if there is a network at all.
	external := "SKIP external (no network)"
	if _, err := net.LookupHost("example.com"); err == nil {
		if _, err := get(client, "http://example.com/"); err == nil {
			external = "external http OK"
			if _, err := get(client, "https://example.com/"); err == nil {
				external = "external http+https OK"
			} else {
				external = "external http OK, https FAILED: " + err.Error()
			}
		}
	}

	fmt.Printf("OK net (loopback OK, local http OK, %s)\n", external)
}

func get(c *http.Client, url string) (string, error) {
	resp, err := c.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

func check(err error, what string) {
	if err != nil {
		fail("%s: %v", what, err)
	}
}

func fail(format string, a ...any) {
	fmt.Printf("FAIL net: "+format+"\n", a...)
	os.Exit(1)
}
