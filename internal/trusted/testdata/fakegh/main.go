// Package main is a CGO-disabled, static test-only gh stand-in. It deliberately
// has no provider credentials or host paths; trusted sandbox tests pass only
// already-safe test paths as direct argv data.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		os.Exit(2)
	}
	switch os.Args[1] {
	case "inspect":
		inspect(os.Args[2:])
	case "probe":
		result := map[string]bool{}
		for _, path := range os.Args[2:] {
			_, err := os.Stat(path)
			result[path] = err == nil
		}
		encoded, _ := json.Marshal(result)
		fmt.Printf("AIRLOCK_PROBE:%s\n", encoded)
	case "spawn":
		if len(os.Args) != 3 {
			os.Exit(2)
		}
		child := exec.Command(os.Args[0], "child", os.Args[2])
		child.Env = os.Environ()
		if err := child.Start(); err != nil {
			os.Exit(91)
		}
		time.Sleep(10 * time.Second)
	case "child":
		if len(os.Args) != 3 {
			os.Exit(2)
		}
		time.Sleep(300 * time.Millisecond)
		_ = os.WriteFile(os.Args[2], []byte("descendant survived"), 0o600)
	default:
		inspect(os.Args[1:])
	}
}

func inspect(argv []string) {
	cwd, _ := os.Getwd()
	writeDenied := false
	if config := os.Getenv("GH_CONFIG_DIR"); config != "" {
		writeDenied = os.WriteFile(filepath.Join(config, "poisoned-alias"), []byte("not persistent"), 0o600) != nil
	}
	encoded, _ := json.Marshal(struct {
		Argv        []string `json:"argv"`
		Env         []string `json:"env"`
		CWD         string   `json:"cwd"`
		WriteDenied bool     `json:"write_denied"`
	}{Argv: argv, Env: os.Environ(), CWD: cwd, WriteDenied: writeDenied})
	fmt.Printf("AIRLOCK_SNAPSHOT:%s\n", encoded)
	// pragma: allowlist secret -- test-only output redaction canary.
	fmt.Printf("\x1b[31mghp_FAKEOUTPUTMUSTNEVERPERSISTOREGRESS0123456789\x00%s", strings.Repeat("private-output", 10000))
}
