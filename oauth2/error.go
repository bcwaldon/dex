package oauth2

const (
	ErrorInvalidClient           = "invalid_client"
	ErrorInvalidGrant            = "invalid_grant"
	ErrorInvalidRequest          = "invalid_request"
	ErrorServerError             = "server_error"
	ErrorUnsupportedGrantType    = "unsupported_grant_type"
	ErrorUnsupportedResponseType = "unsupported_response_type"
)

type Error struct {
	Type string
}

func (e *Error) Error() string {
	return e.Type
}

func NewError(typ string) *Error {
	return &Error{Type: typ}
}
