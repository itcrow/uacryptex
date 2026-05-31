package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "testdata")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("testdata directory not found (run from uacryptex checkout)")
		}
		dir = parent
	}
}

func readTestdata(parts ...string) ([]byte, error) {
	root, err := repoRoot()
	if err != nil {
		return nil, err
	}
	return os.ReadFile(filepath.Join(append([]string{root, "testdata"}, parts...)...))
}
