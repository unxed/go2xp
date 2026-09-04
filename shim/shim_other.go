//go:build !windows || !386

// On platforms other than windows/386 the shim has nothing to do, so importing it
// is free. This lets a cross-platform application keep a single unconditional
// import _ "github.com/unxed/go2xp/shim" in its main package.
package shim
