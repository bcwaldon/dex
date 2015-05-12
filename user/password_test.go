package user

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kylelemons/godebug/pretty"
	"golang.org/x/crypto/bcrypt"
)

func TestNewPasswordInfosFromReader(t *testing.T) {
	PasswordHasher = func(plaintext string) ([]byte, error) {
		return []byte(strings.ToUpper(plaintext)), nil
	}
	defer func() {
		PasswordHasher = DefaultPasswordHasher
	}()

	encodeBase64 := func(s string) string {
		dst := make([]byte, base64.StdEncoding.EncodedLen(len(s)))
		base64.StdEncoding.Encode(dst, []byte(s))
		return string(dst)
	}

	tests := []struct {
		json string
		want []PasswordInfo
	}{
		{
			json: fmt.Sprintf(`[{"userId":"12345","passwordPlaintext":"password"},{"userId":"78901","passwordHash":%q, "passwordExpires":"2006-01-01T15:04:05Z"}]`, encodeBase64("WORDPASS")),
			want: []PasswordInfo{
				{
					UserID:   "12345",
					Password: []byte("PASSWORD"),
				},
				{
					UserID:   "78901",
					Password: []byte("WORDPASS"),
					PasswordExpires: time.Date(2006,
						1, 1, 15, 4, 5, 0, time.UTC),
				},
			},
		},
	}

	for i, tt := range tests {
		r := strings.NewReader(tt.json)
		us, err := newPasswordInfosFromReader(r)
		if err != nil {
			t.Errorf("case %d: want nil err: %v", i, err)
			continue
		}
		if diff := pretty.Compare(tt.want, us); diff != "" {
			t.Errorf("case %d: Compare(want, got): %v", i, diff)
		}
	}
}

func TestNewPasswordFromHash(t *testing.T) {
	tests := []string{
		"test",
		"1",
	}

	for i, plaintext := range tests {
		p, err := NewPasswordFromPlaintext(plaintext)
		if err != nil {
			t.Errorf("case %d: unexpected error: %q", i, err)
			continue
		}
		if err = bcrypt.CompareHashAndPassword([]byte(p), []byte(plaintext)); err != nil {
			t.Errorf("case %d: err comparing hash and plaintext: %q", i, err)
		}
	}
}
