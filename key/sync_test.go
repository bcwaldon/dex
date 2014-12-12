package key

import (
	"reflect"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
)

func TestKeySyncerSync(t *testing.T) {
	fc := clockwork.NewFakeClock()
	now := fc.Now().UTC()

	k1 := generatePrivateKeyStatic(t, 1)
	k2 := generatePrivateKeyStatic(t, 2)
	k3 := generatePrivateKeyStatic(t, 3)
	k4 := generatePrivateKeyStatic(t, 4)

	steps := []struct {
		from    *PrivateKeySet
		advance time.Duration
		want    *PrivateKeySet
	}{
		// on startup, first sync should trigger within a second
		{
			from: &PrivateKeySet{
				keys:        []*PrivateKey{k1},
				ActiveKeyID: k1.KeyID,
				expiresAt:   now.Add(10 * time.Second),
			},
			advance: time.Second,
			want: &PrivateKeySet{
				keys:        []*PrivateKey{k1},
				ActiveKeyID: k1.KeyID,
				expiresAt:   now.Add(10 * time.Second),
			},
		},
		// advance halfway into TTL, triggering sync
		{
			from: &PrivateKeySet{
				keys:        []*PrivateKey{k2, k1},
				ActiveKeyID: k2.KeyID,
				expiresAt:   now.Add(15 * time.Second),
			},
			advance: 5 * time.Second,
			want: &PrivateKeySet{
				keys:        []*PrivateKey{k2, k1},
				ActiveKeyID: k2.KeyID,
				expiresAt:   now.Add(15 * time.Second),
			},
		},

		// advance halfway into TTL, triggering sync that fails
		{
			from: &PrivateKeySet{
				keys:        []*PrivateKey{k3, k2, k1},
				ActiveKeyID: k3.KeyID,
				expiresAt:   now.Add(10 * time.Second),
			},
			advance: 10 * time.Second,
			want: &PrivateKeySet{
				keys:        []*PrivateKey{k2, k1},
				ActiveKeyID: k2.KeyID,
				expiresAt:   now.Add(15 * time.Second),
			},
		},

		// sync retries quickly, and succeeds with fixed data
		{
			from: &PrivateKeySet{
				keys:        []*PrivateKey{k4, k2, k1},
				ActiveKeyID: k4.KeyID,
				expiresAt:   now.Add(25 * time.Second),
			},
			advance: 3 * time.Second,
			want: &PrivateKeySet{
				keys:        []*PrivateKey{k4, k2, k1},
				ActiveKeyID: k4.KeyID,
				expiresAt:   now.Add(25 * time.Second),
			},
		},
	}

	from := NewPrivateKeySetRepo()
	to := NewPrivateKeySetRepo()

	syncer := NewKeySetSyncer(from, to)
	syncer.clock = fc
	stop := syncer.Run()
	defer close(stop)

	for i, st := range steps {
		err := from.Set(st.from)
		if err != nil {
			t.Fatalf("step %d: unable to set keys: %v", i, err)
		}

		fc.Advance(st.advance)
		fc.BlockUntil(1)

		ks, err := to.Get()
		if err != nil {
			t.Fatalf("step %d: unable to get keys: %v", i, err)
		}
		if !reflect.DeepEqual(st.want, ks) {
			t.Fatalf("step %d: incorrect state: want=%#v got=%#v", i, st.want, ks)
		}
	}
}

func TestSync(t *testing.T) {
	fc := clockwork.NewFakeClock()
	now := fc.Now().UTC()

	k1 := generatePrivateKeyStatic(t, 1)
	k2 := generatePrivateKeyStatic(t, 2)
	k3 := generatePrivateKeyStatic(t, 3)

	tests := []struct {
		keySet *PrivateKeySet
		want   time.Duration
	}{
		{
			keySet: &PrivateKeySet{
				keys:        []*PrivateKey{k1},
				ActiveKeyID: k1.KeyID,
				expiresAt:   now.Add(time.Minute),
			},
			want: time.Minute,
		},
		{
			keySet: &PrivateKeySet{
				keys:        []*PrivateKey{k2, k1},
				ActiveKeyID: k2.KeyID,
				expiresAt:   now.Add(time.Minute),
			},
			want: time.Minute,
		},
		{
			keySet: &PrivateKeySet{
				keys:        []*PrivateKey{k3, k2, k1},
				ActiveKeyID: k2.KeyID,
				expiresAt:   now.Add(time.Minute),
			},
			want: time.Minute,
		},
		{
			keySet: &PrivateKeySet{
				keys:        []*PrivateKey{k2, k1},
				ActiveKeyID: k2.KeyID,
				expiresAt:   now.Add(time.Hour),
			},
			want: time.Hour,
		},
	}

	for i, tt := range tests {
		from := NewPrivateKeySetRepo()
		to := NewPrivateKeySetRepo()

		err := from.Set(tt.keySet)
		if err != nil {
			t.Errorf("case %d: unexpected error: %v", i, err)
			continue
		}
		exp, err := Sync(from, to, fc)
		if err != nil {
			t.Errorf("case %d: unexpected error: %v", i, err)
			continue
		}

		if tt.want != exp {
			t.Errorf("case %d: want=%v got=%v", i, tt.want, exp)
		}
	}
}

func TestSyncFail(t *testing.T) {
	fc := clockwork.NewFakeClock()
	now := fc.Now().UTC()

	from := NewPrivateKeySetRepo()
	to := NewPrivateKeySetRepo()

	k1 := generatePrivateKeyStatic(t, 1)
	k2 := generatePrivateKeyStatic(t, 2)
	fixture := &PrivateKeySet{
		keys:        []*PrivateKey{k2, k1},
		ActiveKeyID: k2.KeyID,
		expiresAt:   now.Add(-1 * time.Minute),
	}
	err := from.Set(fixture)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = Sync(from, to, fc)
	if err == nil {
		t.Fatal("expected non-nil error")
	}
}
