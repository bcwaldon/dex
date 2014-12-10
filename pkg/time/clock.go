package time

import (
	"github.com/jonboulle/clockwork"
)

type ClockGetter interface {
	GetClock() clockwork.Clock
}

func Clock(cg ClockGetter) clockwork.Clock {
	c := cg.GetClock()
	if c == nil {
		c = clockwork.NewRealClock()
	}
	return c
}
