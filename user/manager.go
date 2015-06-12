package user

// Manager performs user-related "business-logic" functions on user and related objects.
// This is in contrast to the Repos which perform little more than CRUD operations.
type Manager struct {
	userRepo UserRepo
	pwRepo   PasswordInfoRepo
}

type ManagerOptions struct {
	// This is empty right now but will soon contain configuration information
	// such as passowrd length, name length, password expiration time and other
	// variable policies
}

func NewManager(userRepo UserRepo, pwRepo PasswordInfoRepo, options ManagerOptions) *Manager {
	return &Manager{
		userRepo: userRepo,
		pwRepo:   pwRepo,
	}
}

// RegisterWithRemoteIdentity creates new user and attaches the given remote identity.
func (m *Manager) RegisterWithRemoteIdentity(email string, emailVerified bool, rid RemoteIdentity) (string, error) {
	// TODO(bobbyrullo): here's another racy situation where we could use transactions in the repo.

	if !ValidEmail(email) {
		return "", ErrorInvalidEmail
	}

	var err error
	if _, err = m.userRepo.GetByRemoteIdentity(rid); err == nil {
		return "", ErrorDuplicateRemoteIdentity
	}
	if err != ErrorNotFound {
		return "", err
	}

	if _, err := m.userRepo.GetByEmail(email); err == nil {
		return "", ErrorDuplicateEmail
	}
	if err != ErrorNotFound {
		return "", err
	}

	user := User{
		Email:         email,
		EmailVerified: emailVerified,
	}

	userID, err := m.userRepo.Create(user)
	if err != nil {
		return "", err
	}

	if err := m.userRepo.AddRemoteIdentity(userID, rid); err != nil {
		return "", err
	}

	// TODO: send verification email

	return userID, nil
}

// RegisterWithPassword creates a new user with the given name and password.
// connID is the connector ID of the ConnectorLocal connector.
func (m *Manager) RegisterWithPassword(email, plaintext, connID string) (string, error) {
	// TODO(bobbyrullo): more raciness.

	if !ValidEmail(email) {
		return "", ErrorInvalidEmail
	}

	if !ValidPassword(plaintext) {
		return "", ErrorInvalidPassword
	}

	user := User{
		Email: email,
	}

	userID, err := m.userRepo.Create(user)
	if err != nil {
		return "", err
	}

	rid := RemoteIdentity{
		ConnectorID: connID,
		ID:          userID,
	}
	if err := m.userRepo.AddRemoteIdentity(userID, rid); err != nil {
		return "", err
	}

	password, err := NewPasswordFromPlaintext(plaintext)
	if err != nil {
		return "", err
	}
	pwi := PasswordInfo{
		UserID:   userID,
		Password: password,
	}

	err = m.pwRepo.Create(pwi)
	if err != nil {
		return "", err
	}

	return userID, nil
}
