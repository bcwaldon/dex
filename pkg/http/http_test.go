package http

import (
	"net/url"
	"reflect"
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

func TestMergeQuery(t *testing.T) {
	tests := []struct {
		u string
		q url.Values
		w string
	}{
		// No values
		{
			u: "http://example.com",
			q: nil,
			w: "http://example.com",
		},
		// No additional values
		{
			u: "http://example.com?foo=bar",
			q: nil,
			w: "http://example.com?foo=bar",
		},
		// Simple addition
		{
			u: "http://example.com",
			q: url.Values{
				"foo": []string{"bar"},
			},
			w: "http://example.com?foo=bar",
		},
		// Addition with existing values
		{
			u: "http://example.com?dog=boo",
			q: url.Values{
				"foo": []string{"bar"},
			},
			w: "http://example.com?dog=boo&foo=bar",
		},
		// Merge
		{
			u: "http://example.com?dog=boo",
			q: url.Values{
				"dog": []string{"elroy"},
			},
			w: "http://example.com?dog=boo&dog=elroy",
		},
		// Add and merge
		{
			u: "http://example.com?dog=boo",
			q: url.Values{
				"dog": []string{"elroy"},
				"foo": []string{"bar"},
			},
			w: "http://example.com?dog=boo&dog=elroy&foo=bar",
		},
		// Multivalue merge
		{
			u: "http://example.com?dog=boo",
			q: url.Values{
				"dog": []string{"elroy", "penny"},
			},
			w: "http://example.com?dog=boo&dog=elroy&dog=penny",
		},
	}

	for i, tt := range tests {
		ur, err := url.Parse(tt.u)
		if err != nil {
			t.Errorf("case %d: failed parsing test url: %v, error: %v", i, tt.u, err)
		}

		got := MergeQuery(*ur, tt.q)
		want, err := url.Parse(tt.w)
		if err != nil {
			t.Errorf("case %d: failed parsing want url: %v, error: %v", i, tt.w, err)
		}

		if !reflect.DeepEqual(*want, got) {
			t.Errorf("case %d: want: %v, got: %v", i, *want, got)
		}
	}
}
