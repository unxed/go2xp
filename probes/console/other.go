//go:build !windows

package main

import "fmt"

// The console probe tests Windows-only APIs; on any other platform it has nothing to do.
// The stub exists so that go build ./... works everywhere.
func main() { fmt.Println("SKIP console: not Windows") }
