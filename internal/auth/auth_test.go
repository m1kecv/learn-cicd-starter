package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		headers    http.Header
		wantAPIKey string
		wantErr    error
	}{
		{
			name:       "Valid API Key",
			headers:    http.Header{"Authorization": []string{"ApiKey myApiKey"}},
			wantAPIKey: "myApiKey",
			wantErr:    nil,
		},
		{
			name:    "Missing Authorization Header",
			headers: http.Header{},
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:    "Empty Authorization Header",
			headers: http.Header{"Authorization": []string{""}},
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:    "Malformed Authorization Header - No ApiKey Prefix",
			headers: http.Header{"Authorization": []string{"Bearer myApiKey"}},
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name:    "Malformed Authorization Header - Missing API Key",
			headers: http.Header{"Authorization": []string{"ApiKey"}},
			wantErr: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAPIKey, gotErr := GetAPIKey(tt.headers)

			if gotAPIKey != tt.wantAPIKey {
				t.Errorf("expected API key %s, got %s", tt.wantAPIKey, gotAPIKey)
			}

			if gotErr != nil && tt.wantErr != nil {
				if gotErr.Error() != tt.wantErr.Error() {
					t.Errorf("expected error %v, got %v", tt.wantErr, gotErr)
				}
			} else if gotErr != tt.wantErr {
				t.Errorf("expected error %v, got %v", tt.wantErr, gotErr)
			}
		})
	}
}
