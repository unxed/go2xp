package main

import (
	"fmt"

	"github.com/unxed/go2xp/internal/patch"
)

func doPatch(in, out, profile string) error {
	res, err := patch.Patch(in, out, profile)
	if err != nil {
		return err
	}
	fmt.Printf("patched %s -> %s\n", in, out)
	fmt.Printf("  redirected %d import(s) to polyfills:\n", len(res.Redirected))
	for _, s := range res.Redirected {
		fmt.Println("    ", s)
	}
	if len(res.DroppedDLLs) > 0 {
		fmt.Printf("  dropped whole DLLs: %v\n", res.DroppedDLLs)
	}
	fmt.Printf("  kept %d import(s)\n", res.KeptImports)
	return nil
}

func doVerify(path, profile string) error {
	if err := patch.Verify(path, profile); err != nil {
		return err
	}
	fmt.Printf("verify OK: %s\n", path)
	return nil
}
