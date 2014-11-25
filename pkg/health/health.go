package health

import (
	"fmt"
)

type Checkable interface {
	Healthy() error
}

func Check(checks []Checkable) (err error) {
	errs := []error{}
	for _, c := range checks {
		if e := c.Healthy(); e != nil {
			errs = append(errs, e)
		}
	}

	switch len(errs) {
	case 0:
		err = nil
	case 1:
		err = errs[0]
	default:
		err = fmt.Errorf("multiple health check failure: %v", errs)
	}

	return
}
