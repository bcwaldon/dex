package db

import (
	"log"
	"time"

	"github.com/jonboulle/clockwork"

	ptime "github.com/coreos-inc/auth/pkg/time"
)

type purger interface {
	purge() error
}

type namedPurger struct {
	name string
	purger
}

func NewGarbageCollector(dsn string, ival time.Duration) (*GarbageCollector, error) {
	sRepo, err := NewSessionRepo(dsn)
	if err != nil {
		return nil, err
	}
	skRepo, err := NewSessionKeyRepo(dsn)
	if err != nil {
		return nil, err
	}

	purgers := []namedPurger{
		namedPurger{
			name:   "session",
			purger: sRepo,
		},
		namedPurger{
			name:   "sessionkey",
			purger: skRepo,
		},
	}

	gc := GarbageCollector{
		purgers:  purgers,
		interval: ival,
		clock:    clockwork.NewRealClock(),
	}

	return &gc, nil
}

type GarbageCollector struct {
	purgers  []namedPurger
	interval time.Duration
	clock    clockwork.Clock
}

func (gc *GarbageCollector) Run() chan struct{} {
	stop := make(chan struct{})

	go func() {
		var failing bool
		next := gc.interval
		for {
			select {
			case <-gc.clock.After(next):
				if anyPurgeErrors(purgeAll(gc.purgers)) {
					if !failing {
						failing = true
						next = time.Second
					} else {
						next = ptime.ExpBackoff(next, time.Minute)
					}
					log.Printf("Failed garbage collection, retrying in %v", next)
				} else {
					failing = false
					next = gc.interval
					log.Printf("Garbage collection complete, running again in %v", next)
				}
			case <-stop:
				return
			}
		}
	}()

	return stop
}

type purgeError struct {
	name string
	err  error
}

func anyPurgeErrors(errchan <-chan purgeError) (found bool) {
	for perr := range errchan {
		found = true
		log.Printf("Failed purging %s: %v", perr.name, perr.err)
	}
	return
}

func purgeAll(purgers []namedPurger) <-chan purgeError {
	errchan := make(chan purgeError)
	go func() {
		for _, p := range purgers {
			if err := p.purge(); err != nil {
				errchan <- purgeError{name: p.name, err: err}
			}
		}
		close(errchan)
	}()
	return errchan
}
