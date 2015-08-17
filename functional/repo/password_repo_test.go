package repo

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/kylelemons/godebug/pretty"

	"github.com/coreos-inc/auth/db"
	"github.com/coreos-inc/auth/user"
)

var makeTestPasswordInfoRepo func() user.PasswordInfoRepo

var (
	testPWs = []user.PasswordInfo{
		{
			UserID:   "ID-1",
			Password: []byte("hi."),
		},
	}
)

func init() {
	dsn := os.Getenv("AUTHD_TEST_DSN")
	if dsn == "" {
		makeTestPasswordInfoRepo = makeTestPasswordInfoRepoMem
	} else {
		makeTestPasswordInfoRepo = makeTestPasswordInfoRepoDB(dsn)
	}
}

func makeTestPasswordInfoRepoMem() user.PasswordInfoRepo {
	return user.NewPasswordInfoRepoFromPasswordInfos(testPWs)
}

func makeTestPasswordInfoRepoDB(dsn string) func() user.PasswordInfoRepo {
	return func() user.PasswordInfoRepo {
		c := initDB(dsn)

		repo := db.NewPasswordInfoRepo(c)
		err := user.LoadPasswordInfos(repo, testPWs)
		if err != nil {
			panic(fmt.Sprintf("Unable to add passwordInfos: %v", err))
		}
		return repo
	}
}

func TestCreatePasswordInfo(t *testing.T) {
	tests := []struct {
		pw  user.PasswordInfo
		err error
	}{
		{
			pw: user.PasswordInfo{
				UserID:   "ID-2",
				Password: user.Password("bob@example.com"),
			},
			err: nil,
		},
		{
			pw: user.PasswordInfo{
				UserID:          "ID-3",
				Password:        user.Password("1234"),
				PasswordExpires: time.Now().Round(time.Second).UTC(),
			},
			err: nil,
		},
		{
			pw: user.PasswordInfo{
				UserID:          "ID-1",
				Password:        user.Password("1234"),
				PasswordExpires: time.Now().Round(time.Second).UTC(),
			},
			err: user.ErrorDuplicateID,
		},
		{
			pw: user.PasswordInfo{
				Password:        user.Password("1234"),
				PasswordExpires: time.Now().Round(time.Second).UTC(),
			},
			err: user.ErrorInvalidID,
		},
	}

	for i, tt := range tests {
		repo := makeTestPasswordInfoRepo()
		err := repo.Create(nil, tt.pw)
		if tt.err != nil {
			if err != tt.err {
				t.Errorf("case %d: want=%v, got=%v", i, tt.err, err)
			}
		} else {
			if err != nil {
				t.Errorf("case %d: want nil err, got %v", i, err)
			}

			gotPW, err := repo.Get(nil, tt.pw.UserID)
			if err != nil {
				t.Errorf("case %d: want nil err, got %v", i, err)
			}

			if diff := pretty.Compare(tt.pw, gotPW); diff != "" {
				t.Errorf("case %d: Compare(want, got) = %v", i,
					diff)
			}
		}
	}
}

func TestUpdatePasswordInfo(t *testing.T) {
	tests := []struct {
		pw  user.PasswordInfo
		err error
	}{
		{
			pw: user.PasswordInfo{
				UserID:          "ID-1",
				Password:        user.Password("new_pass"),
				PasswordExpires: time.Now().Round(time.Second).UTC(),
			},
			err: nil,
		},
		{
			pw: user.PasswordInfo{
				UserID:          "ID-2",
				Password:        user.Password("new_pass"),
				PasswordExpires: time.Now().Round(time.Second).UTC(),
			},
			err: user.ErrorNotFound,
		},
		{
			pw: user.PasswordInfo{
				UserID:          "ID-1",
				PasswordExpires: time.Now().Round(time.Second).UTC(),
			},
			err: user.ErrorInvalidPassword,
		},
	}

	for i, tt := range tests {
		repo := makeTestPasswordInfoRepo()
		err := repo.Update(nil, tt.pw)
		if tt.err != nil {
			if err != tt.err {
				t.Errorf("case %d: want=%q, got=%q", i, tt.err, err)
			}
		} else {
			if err != nil {
				t.Errorf("case %d: want nil err, got %q", i, err)
			}

			gotPW, err := repo.Get(nil, tt.pw.UserID)
			if err != nil {
				t.Errorf("case %d: want nil err, got %q", i, err)
			}

			if diff := pretty.Compare(tt.pw, gotPW); diff != "" {
				t.Errorf("case %d: Compare(want, got) = %v", i,
					diff)
			}
		}
	}
}
