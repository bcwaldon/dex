package connector

import (
	"reflect"
	"testing"
)

func TestNewConnectorConfigFromType(t *testing.T) {
	tests := []struct {
		typ  string
		want interface{}
	}{
		{
			typ:  ConnectorTypeLocal,
			want: &ConnectorConfigLocal{},
		},
		{
			typ:  ConnectorTypeOIDC,
			want: &ConnectorConfigOIDC{},
		},
	}

	for i, tt := range tests {
		got, err := NewConnectorConfigFromType(tt.typ)
		if err != nil {
			t.Errorf("case %d: expected nil err: %v", i, err)
			continue
		}
		if !reflect.DeepEqual(tt.want, got) {
			t.Errorf("case %d: want=%v got=%v", i, tt.want, got)
		}
	}
}

func TestNewConnectorConfigFromTypeUnrecognized(t *testing.T) {
	_, err := NewConnectorConfigFromType("foo")
	if err == nil {
		t.Fatalf("Expected non-nil error")
	}
}

func TestNewIDPConnectorConfigFromMap(t *testing.T) {
	tests := []struct {
		m    map[string]interface{}
		want IDPConnectorConfig
	}{
		{
			m: map[string]interface{}{
				"type": "local",
				"id":   "foo",
				"users": []map[string]string{
					{"id": "abc", "name": "ping"},
					{"id": "271", "name": "pong"},
				},
			},
			want: &ConnectorConfigLocal{
				ID: "foo",
				Users: []User{
					User{ID: "abc", Name: "ping"},
					User{ID: "271", Name: "pong"},
				},
			},
		},
		{
			m: map[string]interface{}{
				"type":         "oidc",
				"id":           "bar",
				"issuerURL":    "http://example.com",
				"clientID":     "client123",
				"clientSecret": "whaaaaa",
			},
			want: &ConnectorConfigOIDC{
				ID:           "bar",
				IssuerURL:    "http://example.com",
				ClientID:     "client123",
				ClientSecret: "whaaaaa",
			},
		},
	}

	for i, tt := range tests {
		got, err := newIDPConnectorConfigFromMap(tt.m)
		if err != nil {
			t.Errorf("case %d: want nil error: %v", i, err)
			continue
		}
		if !reflect.DeepEqual(tt.want, got) {
			t.Errorf("case %d: want=%v got=%v", i, tt.want, got)
		}
	}
}

func TestNewIDPConnectorConfigFromMapFail(t *testing.T) {
	tests := []map[string]interface{}{
		// invalid local connector
		map[string]interface{}{
			"type":  "local",
			"users": "invalid",
		},

		// no type
		map[string]interface{}{
			"id": "bar",
		},

		// type not string
		map[string]interface{}{
			"id": 123,
		},
	}

	for i, tt := range tests {
		_, err := newIDPConnectorConfigFromMap(tt)
		if err == nil {
			t.Errorf("case %d: want non-nil error", i)
		}
	}
}
