package usertest

import (
	"fmt"

	"github.com/coreos-inc/auth/user"
)

// NewTestUserRepo returns a test repo whose ids monotonically increase.
// The IDs are in the form { testid-1 testid-2 ... testid-n }
func NewTestUserRepo() (user.UserRepo, error) {
	var idIdx int
	idGenerator := func() (string, error) {
		idIdx++
		return fmt.Sprintf("testid-%d", idIdx), nil
	}

	userRepo := user.NewUserRepoWithIDGenerator(idGenerator)

	return userRepo, nil
}
