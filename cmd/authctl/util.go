package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"strings"
)

func stderr(format string, args ...interface{}) {
	if !strings.HasSuffix(format, "\n") {
		format = format + "\n"
	}
	fmt.Fprintf(os.Stderr, format, args...)
}

func stdout(format string, args ...interface{}) {
	if !strings.HasSuffix(format, "\n") {
		format = format + "\n"
	}
	fmt.Fprintf(os.Stdout, format, args...)
}

func randBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	got, err := rand.Read(b)
	if err != nil {
		return nil, err
	} else if n != got {
		return nil, errors.New("unable to generate enough random data")
	}
	return b, nil
}
