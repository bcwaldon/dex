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
	getErr      bool
	setErr      bool
	cfg         *ProviderConfig
	getCount    int
	getErrCount int
	setCount    int
	setErrCount int
}

func (g *fakeProviderConfigGetterSetter) Get() (ProviderConfig, error) {
	if g.getErr {
		g.getErrCount++
		return ProviderConfig{}, errors.New("error")
	}
	g.getCount++
	return *g.cfg, nil
}

func (g *fakeProviderConfigGetterSetter) Set(cfg ProviderConfig) error {
	if g.setErr {
		g.setErrCount++
		return errors.New("error")
	}
	g.cfg = &cfg
	g.setCount++
	return nil
}

type fakeServer struct {
	cfg    ProviderConfig
	maxAge time.Duration
}

func (s *fakeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := json.Marshal(s.cfg)
	if s.maxAge.Seconds() >= 0 {
		w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(s.maxAge.Seconds())))
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

func TestHTTPProviderConfigGet(t *testing.T) {
	svr := &fakeServer{}
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

func TestSyncerRun(t *testing.T) {
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

// TestSyncerRunGetFailure tests for ProviderConfigGetterSetter.Get() errors
func TestSyncerRunGetFailure(t *testing.T) {
	fc := clockwork.NewFakeClock()
	now := fc.Now().UTC()
	c := &ProviderConfig{
		ExpiresAt: now.Add(10 * time.Second),
	}
	from := &fakeProviderConfigGetterSetter{getErr: true, cfg: c}
	to := &fakeProviderConfigGetterSetter{}
	syncer := NewProviderConfigSyncer(from, to)
	syncer.clock = fc

	stop := syncer.Run()
	defer close(stop)
	fc.BlockUntil(1)

	// ensure get failed
	if from.getCount != 0 || from.getErrCount != 1 {
		t.Fatalf("want: getCount=0, getErrCount=1 got: getCount=%v, getErrCount=%v", from.getCount, from.getErrCount)
	}

	// ensure Set() did not occur
	if to.cfg != nil {
		t.Fatalf("want: to.cfg=nil, got: %v", to.cfg)
	}

	fc.Advance(time.Second)
	fc.BlockUntil(1)

	// ensure retry is attempted after 1s
	if from.getCount != 0 || from.getErrCount != 2 {
		t.Fatalf("want: getCount=0, getErrCount=2 got: getCount=%v, getErrCount=%v", from.getCount, from.getErrCount)
	}

	// ensure Set() did not occur
	if to.cfg != nil {
		t.Fatalf("want: to.cfg=nil, got: %v", to.cfg)
	}
}

// TestSyncerRunSetFailure tests for ProviderConfigGetterSetter.Set() errors
func TestSyncerRunSetFailure(t *testing.T) {
	fc := clockwork.NewFakeClock()
	now := fc.Now().UTC()
	c := &ProviderConfig{
		ExpiresAt: now.Add(10 * time.Second),
	}
	from := &fakeProviderConfigGetterSetter{cfg: c}
	to := &fakeProviderConfigGetterSetter{setErr: true}
	syncer := NewProviderConfigSyncer(from, to)
	syncer.clock = fc

	stop := syncer.Run()
	defer close(stop)
	fc.BlockUntil(1)

	// ensure get was called
	if from.getCount != 1 {
		t.Fatalf("want: getCount=1, got: getCount=%v", from.getCount)
	}

	// ensure set fails
	if to.setCount != 0 || to.setErrCount != 1 {
		t.Fatalf("want: setCount=0, setErrCount=1, got: setCount=%v, setErrCount=%v", to.setCount, to.setErrCount)
	}

	fc.Advance(time.Second)
	fc.BlockUntil(1)

	// ensure retry is attempted after 1s
	if from.getCount != 2 {
		t.Fatalf("want: getCount=1, got: getCount=%v", from.getCount)
	}

	// ensure set fails
	if to.setCount != 0 {
		t.Fatalf("want: setCount=0, got: setCount=%v", to.setCount)
	}
}

// TestSyncerRunExpFailure tests for expired config errors
func TestSyncerRunExpFailure(t *testing.T) {
	fc := clockwork.NewFakeClock()
	now := fc.Now().UTC()
	c := &ProviderConfig{
		ExpiresAt: now,
	}
	from := &fakeProviderConfigGetterSetter{cfg: c}
	to := &fakeProviderConfigGetterSetter{}
	syncer := NewProviderConfigSyncer(from, to)
	syncer.clock = fc

	stop := syncer.Run()
	defer close(stop)
	fc.BlockUntil(1)

	// ensure get was called
	if from.getCount != 1 {
		t.Fatalf("want: getCount=1, got: getCount=%v", from.getCount)
	}

	// ensure config is not set
	if to.cfg != nil {
		t.Fatalf("want: cfg=nil got: cfg=%v", to.cfg)
	}

	fc.Advance(time.Second)
	fc.BlockUntil(1)

	// ensure retry is attempted after 1s
	if from.getCount != 2 {
		t.Fatalf("want: getCount=1, got: getCount=%v", from.getCount)
	}
}
