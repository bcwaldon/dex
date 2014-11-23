package db

import (
	"testing"
)

func TestNewPrivateKeySetRepoInvalidKey(t *testing.T) {
	_, err := NewPrivateKeySetRepo("postgres://127.0.0.1:1111/db", "sharks")
	if err == nil {
		t.Fatalf("Expected non-nil error")
	}
}
