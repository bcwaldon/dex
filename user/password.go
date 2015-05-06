package user

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/coreos-inc/auth/oidc"
)

const (
	bcryptHashCost = 10

	// Blowfish, the algorithm underlying bcrypt, has a maximum
	// password length of 72. We explicitly track and check this
	// since the bcrypt library will silently ignore portions of
	// a password past the first 72 characters.
	maxSecretLength = 72
)

var (
	PasswordHasher = DefaultPasswordHasher

	ErrorInvalidPassword     = errors.New("invalid Password")
	ErrorPasswordHashNoMatch = errors.New("password and hash don't match")
	ErrorPasswordExpired     = errors.New("password has expired")
)

type Hasher func(string) ([]byte, error)

func DefaultPasswordHasher(s string) ([]byte, error) {
	pwHash, err := bcrypt.GenerateFromPassword([]byte(s), bcryptHashCost)
	if err != nil {
		return nil, err
	}
	return Password(pwHash), nil
}

type Password []byte

type PasswordInfo struct {
	UserID string

	Password Password

	PasswordExpires time.Time
}

func (p PasswordInfo) Authenticate(plaintext string) (*oidc.Identity, error) {
	if err := bcrypt.CompareHashAndPassword(p.Password, []byte(plaintext)); err != nil {
		return nil, ErrorPasswordHashNoMatch
	}

	if !p.PasswordExpires.IsZero() && time.Now().After(p.PasswordExpires) {
		return nil, ErrorPasswordExpired
	}

	ident := p.Identity()
	return &ident, nil
}

func (p PasswordInfo) Identity() oidc.Identity {
	return oidc.Identity{
		ID: p.UserID,
	}
}

type PasswordInfoRepo interface {
	Get(id string) (PasswordInfo, error)
	Update(PasswordInfo) error
	Create(PasswordInfo) error
}

func NewPasswordInfoRepo() PasswordInfoRepo {
	return &memPasswordInfoRepo{
		pws: make(map[string]PasswordInfo),
	}
}

type memPasswordInfoRepo struct {
	pws map[string]PasswordInfo
}

func (m *memPasswordInfoRepo) Get(id string) (PasswordInfo, error) {
	pw, ok := m.pws[id]
	if !ok {
		return PasswordInfo{}, ErrorNotFound
	}
	return pw, nil
}

func (m *memPasswordInfoRepo) Create(pw PasswordInfo) error {
	_, ok := m.pws[pw.UserID]
	if ok {
		return ErrorDuplicateID
	}

	if pw.UserID == "" {
		return ErrorInvalidID
	}

	if len(pw.Password) == 0 {
		return ErrorInvalidPassword
	}

	m.pws[pw.UserID] = pw
	return nil
}

func (m *memPasswordInfoRepo) Update(pw PasswordInfo) error {
	if pw.UserID == "" {
		return ErrorInvalidID
	}

	_, ok := m.pws[pw.UserID]
	if !ok {
		return ErrorNotFound
	}

	if len(pw.Password) == 0 {
		return ErrorInvalidPassword
	}

	m.pws[pw.UserID] = pw
	return nil
}

func NewPasswordFromPlaintext(plaintext string) (Password, error) {
	return PasswordHasher(plaintext)
}

func (u *PasswordInfo) UnmarshalJSON(data []byte) error {
	var dec struct {
		UserID            string    `json:"userId"`
		PasswordHash      []byte    `json:"passwordHash"`
		PasswordPlaintext string    `json:"passwordPlaintext"`
		PasswordExpires   time.Time `json:"passwordExpires"`
	}

	err := json.Unmarshal(data, &dec)
	if err != nil {
		return fmt.Errorf("invalid User entry: %v", err)
	}

	u.UserID = dec.UserID

	u.PasswordExpires = dec.PasswordExpires

	if len(dec.PasswordHash) != 0 {
		if dec.PasswordPlaintext != "" {
			return ErrorInvalidPassword
		}
		u.Password = Password(dec.PasswordHash)
	} else if dec.PasswordPlaintext != "" {
		u.Password, err = NewPasswordFromPlaintext(dec.PasswordPlaintext)
		if err != nil {
			return err
		}

	}
	return nil
}

func newPasswordInfosFromReader(r io.Reader) ([]PasswordInfo, error) {
	var pws []PasswordInfo
	err := json.NewDecoder(r).Decode(&pws)
	return pws, err
}

func readPasswordInfosFromFile(loc string) ([]PasswordInfo, error) {
	pwf, err := os.Open(loc)
	if err != nil {
		return nil, fmt.Errorf("unable to read password info from file %q: %v", loc, err)
	}

	return newPasswordInfosFromReader(pwf)
}

func LoadPasswordInfos(repo PasswordInfoRepo, pws []PasswordInfo) error {
	for i, pw := range pws {
		err := repo.Create(pw)
		if err != nil {
			return fmt.Errorf("error loading PasswordInfo[%d]: %q", i, err)
		}
	}
	return nil
}

func NewPasswordInfoRepoFromPasswordInfos(pws []PasswordInfo) PasswordInfoRepo {
	memRepo := NewPasswordInfoRepo().(*memPasswordInfoRepo)
	for _, pw := range pws {
		memRepo.pws[pw.UserID] = pw
	}
	return memRepo
}

func NewPasswordInfoRepoFromFile(loc string) (PasswordInfoRepo, error) {
	pws, err := readPasswordInfosFromFile(loc)
	if err != nil {
		return nil, err
	}

	return NewPasswordInfoRepoFromPasswordInfos(pws), nil
}
