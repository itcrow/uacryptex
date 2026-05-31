package uacryptex_test

import (
	"os"
	"path/filepath"
	"testing"
)

func readTestdata(t *testing.T, parts ...string) []byte {
	if t != nil {
		t.Helper()
	}
	root := repoRoot(t)
	full := filepath.Join(append([]string{root, "testdata"}, parts...)...)
	data, err := os.ReadFile(full)
	if err != nil {
		if t != nil {
			t.Fatalf("read testdata %s: %v", full, err)
		}
		panic(err)
	}
	return data
}

func repoRoot(t *testing.T) string {
	if t != nil {
		t.Helper()
	}
	dir, err := os.Getwd()
	if err != nil {
		if t != nil {
			t.Fatal(err)
		}
		panic(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "testdata")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			if t != nil {
				t.Fatal("testdata directory not found")
			}
			panic("testdata directory not found")
		}
		dir = parent
	}
}
