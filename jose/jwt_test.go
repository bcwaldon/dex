package jose

import (
	"reflect"
	"testing"
)

var jwtParseTests = []struct {
	r string
	h JOSEHeader
	c Claims
}{
	{
		// Example from JWT spec:
		// http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html#ExampleJWT
		"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		JOSEHeader{
			"typ": "JWT",
			"alg": "HS256",
		},
		Claims{
			"iss": "joe",
			// NOTE: test numbers must be floats for equality checks to work since values are converted form interface{} to float64 by default.
			"exp": 1300819380.0,
			"http://example.com/is_root": true,
		},
	},
}

func TestParseJWT(t *testing.T) {

	for i, tt := range jwtParseTests {
		jwt, err := ParseJWT(tt.r)
		if err != nil {
			t.Errorf("raw token should parse. test: %d. expected: valid, actual: invalid. err=%v", i, err)
		}

		if !reflect.DeepEqual(tt.h, jwt.Header) {
			t.Errorf("JOSE headers should match. test: %d. expected: %v, actual: %v", i, tt.h, jwt.Header)
		}

		claims, err := jwt.Claims()
		if err != nil {
			t.Errorf("test: %d. expected: valid claim parsing. err=%v", i, err)
		}
		if !reflect.DeepEqual(tt.c, claims) {
			t.Errorf("claims should match. test: %d. expected: %v, actual: %v", i, tt.c, claims)
		}

		enc := jwt.Encode()
		if enc != tt.r {
			t.Errorf("encoded jwt should match raw jwt. test: %d. expected: %v, actual: %v", i, tt.r, enc)
		}
	}

}