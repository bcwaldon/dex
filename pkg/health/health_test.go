package health

import (
	"errors"
	"testing"
)

type staticCheckable struct {
	healthy bool
}

func (c staticCheckable) Healthy() (err error) {
	if !c.healthy {
		err = errors.New("unhealthy")
	}
	return
}

func TestCheck(t *testing.T) {
	tests := []struct {
		ch []Checkable
		ok bool
	}{
		{
			ch: []Checkable{},
			ok: true,
		},
		{
			ch: []Checkable{staticCheckable{true}},
			ok: true,
		},
		{
			ch: []Checkable{staticCheckable{false}},
			ok: false,
		},
		{
			ch: []Checkable{staticCheckable{true}, staticCheckable{false}},
			ok: false,
		},
	}

	for i, tt := range tests {
		if err := Check(tt.ch); err != nil {
			if tt.ok {
				t.Errorf("case %d: want: healhty, got: %v", i, err)
			}
		} else if !tt.ok {
			t.Errorf("case %d: want: unhealhty, got: healhty", i)
		}
	}
}
