package db

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/coopernurse/gorp"
	"github.com/coreos-inc/auth/refresh"
	"golang.org/x/crypto/bcrypt"
)

const (
	refreshTokenTableName = "authd_refreshtoken"
)

func init() {
	register(table{
		name:    refreshTokenTableName,
		model:   refreshTokenModel{},
		autoinc: true,
		pkey:    []string{"id"},
	})
}

type refreshTokenRepo struct {
	dbMap          *gorp.DbMap
	tokenGenerator refresh.RefreshTokenGenerator
}

type refreshTokenModel struct {
	ID          int64  `db:"id"`
	PayloadHash string `db:"payload_hash"`
	// TODO(yifan): Use some sort of foreign key to manage database level
	// data integrity.
	UserID   string `db:"user_id"`
	ClientID string `db:"client_id"`
}

// buildToken combines the token ID and token payload to create a new token.
func buildToken(tokenID int64, tokenPayload string) string {
	return fmt.Sprintf("%d%s%s", tokenID, refresh.TokenDelimer, tokenPayload)
}

// parseToken parses a token and returns the token ID and token payload.
func parseToken(token string) (int64, string, error) {
	parts := strings.SplitN(token, refresh.TokenDelimer, 2)
	if len(parts) != 2 {
		return -1, "", refresh.ErrorInvalidToken
	}
	id, err := strconv.ParseInt(parts[0], 0, 64)
	if err != nil {
		return -1, "", refresh.ErrorInvalidToken
	}
	return id, parts[1], nil
}

func checkTokenPayload(payloadHash, payload string) error {
	if err := bcrypt.CompareHashAndPassword([]byte(payloadHash), []byte(payload)); err != nil {
		switch err {
		case bcrypt.ErrMismatchedHashAndPassword:
			return refresh.ErrorInvalidToken
		default:
			return err
		}
	}
	return nil
}

func NewRefreshTokenRepo(dbm *gorp.DbMap) refresh.RefreshTokenRepo {
	return &refreshTokenRepo{
		dbMap:          dbm,
		tokenGenerator: refresh.DefaultRefreshTokenGenerator,
	}
}

func (r *refreshTokenRepo) Create(userID, clientID string) (string, error) {
	if userID == "" {
		return "", refresh.ErrorInvalidUserID
	}
	if clientID == "" {
		return "", refresh.ErrorInvalidClientID
	}

	// TODO(yifan): Check the number of tokens given to the client-user pair.
	tokenPayload, err := r.tokenGenerator.Generate()
	if err != nil {
		return "", err
	}

	payloadHash, err := bcrypt.GenerateFromPassword([]byte(tokenPayload), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	record := &refreshTokenModel{
		PayloadHash: string(payloadHash),
		UserID:      userID,
		ClientID:    clientID,
	}

	if err := r.dbMap.Insert(record); err != nil {
		return "", err
	}

	return buildToken(record.ID, tokenPayload), nil
}

func (r *refreshTokenRepo) Verify(clientID, token string) (string, error) {
	tokenID, tokenPayload, err := parseToken(token)
	if err != nil {
		return "", err
	}

	record, err := r.get(nil, tokenID)
	if err != nil {
		return "", err
	}

	if record.ClientID != clientID {
		return "", refresh.ErrorInvalidClientID
	}

	if err := checkTokenPayload(record.PayloadHash, tokenPayload); err != nil {
		return "", err
	}

	return record.UserID, nil
}

func (r *refreshTokenRepo) Revoke(userID, token string) error {
	tokenID, tokenPayload, err := parseToken(token)
	if err != nil {
		return err
	}

	record, err := r.get(nil, tokenID)
	if err != nil {
		return err
	}

	if record.UserID != userID {
		return refresh.ErrorInvalidUserID
	}

	if err := checkTokenPayload(record.PayloadHash, tokenPayload); err != nil {
		return err
	}

	deleted, err := r.dbMap.Delete(record)
	if err != nil {
		return err
	}
	if deleted == 0 {
		return refresh.ErrorInvalidToken
	}

	return nil
}

func (r *refreshTokenRepo) executor(tx *gorp.Transaction) gorp.SqlExecutor {
	if tx == nil {
		return r.dbMap
	}
	return tx
}

func (r *refreshTokenRepo) get(tx *gorp.Transaction, tokenID int64) (*refreshTokenModel, error) {
	ex := r.executor(tx)
	result, err := ex.Get(refreshTokenModel{}, tokenID)
	if err != nil {
		return nil, err
	}

	if result == nil {
		return nil, refresh.ErrorInvalidToken
	}

	record, ok := result.(*refreshTokenModel)
	if !ok {
		return nil, errors.New("unrecognized model")
	}
	return record, nil
}
