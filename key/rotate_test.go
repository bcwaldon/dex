package key

import (
	"reflect"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
)

func generatePrivateRSAKeySerialFunc(t *testing.T) GeneratePrivateRSAKeyFunc {
	var n int
	return func() (*privateRSAKey, error) {
		n++
		return generatePrivateRSAKeyStatic(t, n), nil
	}
}

func TestRotate(t *testing.T) {
	now := time.Now()
	k1 := generatePrivateRSAKeyStatic(t, 1)
	k2 := generatePrivateRSAKeyStatic(t, 2)
	k3 := generatePrivateRSAKeyStatic(t, 3)

	tests := []struct {
		start *PrivateKeySet
		key   PrivateKey
		keep  int
		exp   time.Time
		want  *PrivateKeySet
	}{
		// add first key
		{
			start: &PrivateKeySet{},
			key:   k1,
			keep:  2,
			exp:   now.Add(time.Second),
			want: &PrivateKeySet{
				keys:        []PrivateKey{k1},
				activeKeyID: k1.id,
				expiresAt:   now.Add(time.Second),
			},
		},
		// add second key
		{
			start: &PrivateKeySet{
				keys:        []PrivateKey{k1},
				activeKeyID: k1.id,
				expiresAt:   now,
			},
			key:  k2,
			keep: 2,
			exp:  now.Add(time.Second),
			want: &PrivateKeySet{
				keys:        []PrivateKey{k2, k1},
				activeKeyID: k2.id,
				expiresAt:   now.Add(time.Second),
			},
		},
		// rotate in third key
		{
			start: &PrivateKeySet{
				keys:        []PrivateKey{k2, k1},
				activeKeyID: k2.id,
				expiresAt:   now,
			},
			key:  k3,
			keep: 2,
			exp:  now.Add(time.Second),
			want: &PrivateKeySet{
				keys:        []PrivateKey{k3, k2},
				activeKeyID: k3.id,
				expiresAt:   now.Add(time.Second),
			},
		},
	}

	for i, tt := range tests {
		repo := NewPrivateKeySetRepo()
		repo.Set(tt.start)
		rotatePrivateKeys(repo, tt.key, tt.keep, tt.exp)
		got, err := repo.Get()
		if err != nil {
			t.Errorf("case %d: unexpected error: %v", i, err)
			continue
		}
		if !reflect.DeepEqual(tt.want, got) {
			t.Errorf("case %d: unexpected result: want=%#v got=%#v", i, tt.want, got)
		}
	}
}

func TestPrivateKeyRotatorRun(t *testing.T) {
	fc := clockwork.NewFakeClock()
	now := fc.Now().UTC()

	k1 := generatePrivateRSAKeyStatic(t, 1)
	k2 := generatePrivateRSAKeyStatic(t, 2)
	k3 := generatePrivateRSAKeyStatic(t, 3)
	k4 := generatePrivateRSAKeyStatic(t, 4)

	kRepo := NewPrivateKeySetRepo()
	krot := NewPrivateKeyRotator(kRepo, 4*time.Second)
	krot.clock = fc
	krot.generateKey = generatePrivateRSAKeySerialFunc(t)

	steps := []*PrivateKeySet{
		&PrivateKeySet{
			keys:        []PrivateKey{k1},
			activeKeyID: k1.id,
			expiresAt:   now.Add(4 * time.Second),
		},
		&PrivateKeySet{
			keys:        []PrivateKey{k2, k1},
			activeKeyID: k2.id,
			expiresAt:   now.Add(6 * time.Second),
		},
		&PrivateKeySet{
			keys:        []PrivateKey{k3, k2},
			activeKeyID: k3.id,
			expiresAt:   now.Add(8 * time.Second),
		},
		&PrivateKeySet{
			keys:        []PrivateKey{k4, k3},
			activeKeyID: k4.id,
			expiresAt:   now.Add(10 * time.Second),
		},
	}

	stop := krot.Run()
	defer close(stop)

	for i, st := range steps {
		// wait for the rotater to get sleepy
		fc.BlockUntil(1)

		got, err := kRepo.Get()
		if err != nil {
			t.Fatalf("step %d: unexpected error: %v", i, err)
		}
		if !reflect.DeepEqual(st, got) {
			t.Fatalf("step %d: unexpected state: want=%#v got=%#v", i, st, got)
		}
		fc.Advance(2 * time.Second)
	}
}

func TestPrivateKeyRotatorExpiresAt(t *testing.T) {
	fc := clockwork.NewFakeClock()
	krot := &PrivateKeyRotator{
		clock: fc,
		ttl:   time.Minute,
	}
	got := krot.expiresAt()
	want := fc.Now().UTC().Add(time.Minute)
	if !reflect.DeepEqual(want, got) {
		t.Errorf("Incorrect expiration time: want=%v got=%v", want, got)
	}
}
