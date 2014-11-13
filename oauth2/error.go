package oauth2

type Error string

func (e *Error) Error() string {
	return string(*e)
}

func NewError(msg string) *Error {
	err := Error(msg)
	return &err
}

var (
	ErrorInvalidClient = NewError("invalid_client")
	ErrorInvalidGrant  = NewError("invalid_grant")
	ErrorServerError   = NewError("server_error")
)
