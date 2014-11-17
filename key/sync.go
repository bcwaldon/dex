package key

import (
	"errors"
	"log"
	"time"

	"github.com/jonboulle/clockwork"

	ptime "github.com/coreos-inc/auth/pkg/time"
)

func NewKeySetSyncer(r ReadableKeySetRepo, w WritableKeySetRepo) *KeySetSyncer {
	return &KeySetSyncer{
		readable: r,
		writable: w,
		clock:    clockwork.NewRealClock(),
	}
}

type KeySetSyncer struct {
	readable ReadableKeySetRepo
	writable WritableKeySetRepo
	clock    clockwork.Clock
}

func (s *KeySetSyncer) Run() chan struct{} {
	stop := make(chan struct{})
	go func() {
		var failing bool
		var next time.Duration
		for {
			exp, err := sync(s.readable, s.writable, s.clock)
			if err != nil {
				if !failing {
					failing = true
					next = time.Second
				} else {
					next = ptime.ExpBackoff(next, time.Minute)
				}
				log.Printf("Failed syncing key set, retrying in %v: %v", next, err)
			} else {
				failing = false
				next = exp / 2
				log.Printf("Synced key set, checking again in %v", next)
			}

			select {
			case <-s.clock.After(next):
				continue
			case <-stop:
				return
			}
		}
	}()

	return stop
}

func sync(r ReadableKeySetRepo, w WritableKeySetRepo, clock clockwork.Clock) (exp time.Duration, err error) {
	var ks KeySet
	ks, err = r.Get()
	if err != nil {
		return
	}

	diff := ks.ExpiresAt().Sub(clock.Now().UTC())
	if diff <= 0 {
		err = errors.New("key set expired")
		return
	}

	if err = w.Set(ks); err != nil {
		return
	}

	exp = diff
	return
}
