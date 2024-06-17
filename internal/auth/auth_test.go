package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name           string
		headers        http.Header
		expectedAPIKey string
		expectedError  error
	}{
		{
			name:           "No Authorization Header",
			headers:        http.Header{},
			expectedAPIKey: "",
			expectedError:  ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Authorization Header",
			headers: http.Header{
				"Authorization": []string{"Bearer some_token"},
			},
			expectedAPIKey: "",
			expectedError:  errors.New("malformed authorization header"),
		},
		{
			name: "Valid Authorization Header",
			headers: http.Header{
				"Authorization": []string{"ApiKey valid_api_key"},
			},
			expectedAPIKey: "valid_api_key",
			expectedError:  nil,
		},
		{
			name: "Invalid Authorization Scheme",
			headers: http.Header{
				"Authorization": []string{"Basic some_token"},
			},
			expectedAPIKey: "",
			expectedError:  errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiKey, err := GetAPIKey(tt.headers)
			if apiKey != tt.expectedAPIKey {
				t.Errorf("expected API key %q, got %q", tt.expectedAPIKey, apiKey)
			}
			if (err != nil && tt.expectedError == nil) || (err == nil && tt.expectedError != nil) || (err != nil && err.Error() != tt.expectedError.Error()) {
				t.Errorf("expected error %v, got %v", tt.expectedError, err)
			}
		})
	}
}
