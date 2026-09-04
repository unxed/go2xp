package main

// Allow the windows/386 patcher to patch itself for use on XP, including export dumps.
// The shim is empty on other platforms.
import _ "github.com/unxed/go2xp/shim"
