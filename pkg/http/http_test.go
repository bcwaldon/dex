package http

import (
	"testing"
)

func TestCacheControlMaxAgeSuccess(t *testing.T) {
	tests := []struct {
		hdr     string
		wantAge int
		wantOK  bool
	}{
		{"max-age=12", 12, true},
		{"public, max-age=12", 12, true},
		{"public, max-age=40192, must-revalidate", 40192, true},
		{"public, not-max-age=12, must-revalidate", 0, false},
	}

	for i, tt := range tests {
		age, ok, err := CacheControlMaxAge(tt.hdr)
		if err != nil {
			t.Errorf("case %d: err=%v", i, err)
		}
		if tt.wantAge != age {
			t.Errorf("case %d: want=%d got=%d", i, tt.wantAge, age)
		}
		if tt.wantOK != ok {
			t.Errorf("case %d: incorrect ok value: want=%t got=%t", i, tt.wantOK, ok)
		}
	}
}

func TestCacheControlMaxAgeFail(t *testing.T) {
	tests := []string{
		"max-age=aasdf",
		"max-age=",
		"max-age",
	}

	for i, tt := range tests {
		_, _, err := CacheControlMaxAge(tt)
		if err == nil {
			t.Errorf("case %d: want non-nil err", i)
		}
	}
}
