package oidc

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"testing"
	"time"

	phttp "github.com/coreos-inc/auth/pkg/http"

	"github.com/jonboulle/clockwork"
)

type fakeProviderConfigGetterSetter struct {
	cfg      *ProviderConfig
	getCount int
	setCount int
}

func (g *fakeProviderConfigGetterSetter) Get() (ProviderConfig, error) {
	g.getCount++
	return *g.cfg, nil
}

func (g *fakeProviderConfigGetterSetter) Set(cfg ProviderConfig) error {
	g.cfg = &cfg
	g.setCount++
	return nil
}

type fakeProviderConfigHandler struct {
	cfg    ProviderConfig
	maxAge time.Duration
}

func (s *fakeProviderConfigHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := json.Marshal(s.cfg)
	if s.maxAge.Seconds() >= 0 {
		w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(s.maxAge.Seconds())))
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

func TestHTTPProviderConfigGetter(t *testing.T) {
	svr := &fakeProviderConfigHandler{}
	hc := &phttp.HandlerClient{Handler: svr}
	fc := clockwork.NewFakeClock()
	now := fc.Now().UTC()

	tests := []struct {
		dsc string
		age time.Duration
		cfg ProviderConfig
		ok  bool
	}{
		// everything is good
		{
			dsc: "https://example.com",
			age: time.Minute,
			cfg: ProviderConfig{
				Issuer:    "https://example.com",
				ExpiresAt: now.Add(time.Minute),
			},
			ok: true,
		},
		// iss and disco url differ by scheme only (how google works)
		{
			dsc: "https://example.com",
			age: time.Minute,
			cfg: ProviderConfig{
				Issuer:    "example.com",
				ExpiresAt: now.Add(time.Minute),
			},
			ok: true,
		},
		// issuer and discovery URL mismatch
		{
			dsc: "https://foo.com",
			age: time.Minute,
			cfg: ProviderConfig{
				Issuer:    "https://example.com",
				ExpiresAt: now.Add(time.Minute),
			},
			ok: false,
		},
		// missing cache header
		{
			dsc: "https://example.com",
			age: -1,
			cfg: ProviderConfig{
				Issuer: "https://example.com",
			},
			ok: false,
		},
	}

	for i, tt := range tests {
		svr.cfg = tt.cfg
		svr.maxAge = tt.age
		getter := NewHTTPProviderConfigGetter(hc, tt.dsc)
		getter.clock = fc

		got, err := getter.Get()
		if err != nil {
			if tt.ok {
				t.Fatalf("test %d: unexpected error: %v", i, err)
			}
			continue
		}

		if !tt.ok {
			t.Fatalf("test %d: expected error", i)
			continue
		}

		if !reflect.DeepEqual(tt.cfg, got) {
			t.Fatalf("test %d: want: %#v, got: %#v", i, tt.cfg, got)
		}
	}
}

func TestProviderConfigSyncerRun(t *testing.T) {
	c1 := &ProviderConfig{
		Issuer: "http://first.example.com",
	}
	c2 := &ProviderConfig{
		Issuer: "http://second.example.com",
	}

	tests := []struct {
		first     *ProviderConfig
		advance   time.Duration
		second    *ProviderConfig
		firstExp  time.Duration
		secondExp time.Duration
		count     int
	}{
		// exp is 10s, should have same config after 1s
		{
			first:     c1,
			firstExp:  time.Duration(10 * time.Second),
			advance:   time.Second,
			second:    c1,
			secondExp: time.Duration(10 * time.Second),
			count:     1,
		},
		// exp is 10s, should have new config after 10/2 = 5s
		{
			first:     c1,
			firstExp:  time.Duration(10 * time.Second),
			advance:   time.Duration(5 * time.Second),
			second:    c2,
			secondExp: time.Duration(10 * time.Second),
			count:     2,
		},
		// exp is 20s, should have new config after 20/2 = 10s
		{
			first:     c1,
			firstExp:  time.Duration(20 * time.Second),
			advance:   time.Duration(10 * time.Second),
			second:    c2,
			secondExp: time.Duration(30 * time.Second),
			count:     2,
		},
	}

	assertCfg := func(i int, to *fakeProviderConfigGetterSetter, want ProviderConfig) {
		got, err := to.Get()
		if err != nil {
			t.Fatalf("test %d: unable to get config: %v", i, err)
		}
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("test %d: incorrect state:\nwant=%#v\ngot=%#v", i, want, got)
		}
	}

	for i, tt := range tests {
		from := &fakeProviderConfigGetterSetter{}
		to := &fakeProviderConfigGetterSetter{}

		fc := clockwork.NewFakeClock()
		now := fc.Now().UTC()
		syncer := NewProviderConfigSyncer(from, to)
		syncer.clock = fc

		tt.first.ExpiresAt = now.Add(tt.firstExp)
		tt.second.ExpiresAt = now.Add(tt.secondExp)
		if err := from.Set(*tt.first); err != nil {
			t.Fatalf("test %d: unexpected error: %v", i, err)
		}

		stop := syncer.Run()
		defer close(stop)
		fc.BlockUntil(1)

		// first sync
		assertCfg(i, to, *tt.first)

		if err := from.Set(*tt.second); err != nil {
			t.Fatalf("test %d: unexpected error: %v", i, err)
		}

		fc.Advance(tt.advance)
		fc.BlockUntil(1)

		// second sync
		assertCfg(i, to, *tt.second)

		if tt.count != from.getCount {
			t.Fatalf("test %d: want: %v, got: %v", i, tt.count, from.getCount)
		}
	}
}

type staticProviderConfigGetter struct {
	cfg ProviderConfig
	err error
}

func (g *staticProviderConfigGetter) Get() (ProviderConfig, error) {
	return g.cfg, g.err
}

type staticProviderConfigSetter struct {
	cfg *ProviderConfig
	err error
}

func (s *staticProviderConfigSetter) Set(cfg ProviderConfig) error {
	s.cfg = &cfg
	return s.err
}

func TestProviderConfigSyncerSyncFailure(t *testing.T) {
	fc := clockwork.NewFakeClock()

	tests := []struct {
		from *staticProviderConfigGetter
		to   *staticProviderConfigSetter

		// want indicates what ProviderConfig should be passed to Set.
		// If nil, the Set should not be called.
		want *ProviderConfig
	}{
		// generic Get failure
		{
			from: &staticProviderConfigGetter{err: errors.New("fail")},
			to:   &staticProviderConfigSetter{},
			want: nil,
		},
		// generic Set failure
		{
			from: &staticProviderConfigGetter{cfg: ProviderConfig{ExpiresAt: fc.Now().Add(time.Minute)}},
			to:   &staticProviderConfigSetter{err: errors.New("fail")},
			want: &ProviderConfig{ExpiresAt: fc.Now().Add(time.Minute)},
		},
	}

	for i, tt := range tests {
		pcs := &ProviderConfigSyncer{
			from:  tt.from,
			to:    tt.to,
			clock: fc,
		}
		_, err := pcs.sync()
		if err == nil {
			t.Errorf("case %d: expected non-nil error", i)
		}
		if !reflect.DeepEqual(tt.want, tt.to.cfg) {
			t.Errorf("case %d: Set mismatch: want=%#v got=%#v", i, tt.want, tt.to.cfg)
		}
	}
}
