package main

import (
	"reflect"
	"testing"
)

func TestParseCORSOrigins(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: nil,
		},
		{
			name:     "single wildcard",
			input:    "*",
			expected: []string{"*"},
		},
		{
			name:     "single origin",
			input:    "https://example.com",
			expected: []string{"https://example.com"},
		},
		{
			name:     "multiple origins",
			input:    "https://example.com,https://another.com",
			expected: []string{"https://example.com", "https://another.com"},
		},
		{
			name:     "origins with spaces",
			input:    "https://example.com, https://another.com, http://localhost:3000",
			expected: []string{"https://example.com", "https://another.com", "http://localhost:3000"},
		},
		{
			name:     "origins with extra spaces",
			input:    "  https://example.com  ,  https://another.com  ",
			expected: []string{"https://example.com", "https://another.com"},
		},
		{
			name:     "wildcard with other origins",
			input:    "*,https://example.com",
			expected: []string{"*", "https://example.com"},
		},
		{
			name:     "trailing comma",
			input:    "https://example.com,",
			expected: []string{"https://example.com"},
		},
		{
			name:     "leading comma",
			input:    ",https://example.com",
			expected: []string{"https://example.com"},
		},
		{
			name:     "multiple commas",
			input:    "https://example.com,,https://another.com",
			expected: []string{"https://example.com", "https://another.com"},
		},
		{
			name:     "only commas and spaces",
			input:    "  , , ,  ",
			expected: []string{},
		},
		{
			name:     "localhost origins",
			input:    "http://localhost:3000,http://localhost:8080",
			expected: []string{"http://localhost:3000", "http://localhost:8080"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseCORSOrigins(tt.input)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("parseCORSOrigins(%q) = %v, expected %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestGetEnv(t *testing.T) {
	tests := []struct {
		name         string
		key          string
		defaultValue string
		envValue     string
		setEnv       bool
		expected     string
	}{
		{
			name:         "env var not set, use default",
			key:          "TEST_VAR_NOT_SET",
			defaultValue: "default-value",
			setEnv:       false,
			expected:     "default-value",
		},
		{
			name:         "env var set, use env value",
			key:          "TEST_VAR_SET",
			defaultValue: "default-value",
			envValue:     "env-value",
			setEnv:       true,
			expected:     "env-value",
		},
		{
			name:         "env var set to empty string, use empty string",
			key:          "TEST_VAR_EMPTY",
			defaultValue: "default-value",
			envValue:     "",
			setEnv:       true,
			expected:     "default-value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up after test
			defer func() {
				if tt.setEnv {
					t.Setenv(tt.key, "")
				}
			}()

			if tt.setEnv {
				t.Setenv(tt.key, tt.envValue)
			}

			result := getEnv(tt.key, tt.defaultValue)
			if result != tt.expected {
				t.Errorf("getEnv(%q, %q) = %q, expected %q", tt.key, tt.defaultValue, result, tt.expected)
			}
		})
	}
}

func TestGetEnvInt(t *testing.T) {
	tests := []struct {
		name         string
		key          string
		defaultValue int
		envValue     string
		setEnv       bool
		expected     int
	}{
		{
			name:         "env var not set, use default",
			key:          "TEST_INT_NOT_SET",
			defaultValue: 42,
			setEnv:       false,
			expected:     42,
		},
		{
			name:         "env var set to valid int",
			key:          "TEST_INT_VALID",
			defaultValue: 42,
			envValue:     "123",
			setEnv:       true,
			expected:     123,
		},
		{
			name:         "env var set to invalid int",
			key:          "TEST_INT_INVALID",
			defaultValue: 42,
			envValue:     "not-a-number",
			setEnv:       true,
			expected:     42,
		},
		{
			name:         "env var set to empty string",
			key:          "TEST_INT_EMPTY",
			defaultValue: 42,
			envValue:     "",
			setEnv:       true,
			expected:     42,
		},
		{
			name:         "env var set to zero",
			key:          "TEST_INT_ZERO",
			defaultValue: 42,
			envValue:     "0",
			setEnv:       true,
			expected:     0,
		},
		{
			name:         "env var set to negative",
			key:          "TEST_INT_NEGATIVE",
			defaultValue: 42,
			envValue:     "-10",
			setEnv:       true,
			expected:     -10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up after test
			defer func() {
				if tt.setEnv {
					t.Setenv(tt.key, "")
				}
			}()

			if tt.setEnv {
				t.Setenv(tt.key, tt.envValue)
			}

			result := getEnvInt(tt.key, tt.defaultValue)
			if result != tt.expected {
				t.Errorf("getEnvInt(%q, %d) = %d, expected %d", tt.key, tt.defaultValue, result, tt.expected)
			}
		})
	}
}

func TestGetEnvBool(t *testing.T) {
	tests := []struct {
		name         string
		key          string
		defaultValue bool
		envValue     string
		setEnv       bool
		expected     bool
	}{
		{
			name:         "env var not set, use default true",
			key:          "TEST_BOOL_NOT_SET_TRUE",
			defaultValue: true,
			setEnv:       false,
			expected:     true,
		},
		{
			name:         "env var not set, use default false",
			key:          "TEST_BOOL_NOT_SET_FALSE",
			defaultValue: false,
			setEnv:       false,
			expected:     false,
		},
		{
			name:         "env var set to 'true'",
			key:          "TEST_BOOL_TRUE",
			defaultValue: false,
			envValue:     "true",
			setEnv:       true,
			expected:     true,
		},
		{
			name:         "env var set to '1'",
			key:          "TEST_BOOL_ONE",
			defaultValue: false,
			envValue:     "1",
			setEnv:       true,
			expected:     true,
		},
		{
			name:         "env var set to 'yes'",
			key:          "TEST_BOOL_YES",
			defaultValue: false,
			envValue:     "yes",
			setEnv:       true,
			expected:     true,
		},
		{
			name:         "env var set to 'false'",
			key:          "TEST_BOOL_FALSE",
			defaultValue: true,
			envValue:     "false",
			setEnv:       true,
			expected:     false,
		},
		{
			name:         "env var set to '0'",
			key:          "TEST_BOOL_ZERO",
			defaultValue: true,
			envValue:     "0",
			setEnv:       true,
			expected:     false,
		},
		{
			name:         "env var set to 'no'",
			key:          "TEST_BOOL_NO",
			defaultValue: true,
			envValue:     "no",
			setEnv:       true,
			expected:     false,
		},
		{
			name:         "env var set to empty string",
			key:          "TEST_BOOL_EMPTY",
			defaultValue: true,
			envValue:     "",
			setEnv:       true,
			expected:     true,
		},
		{
			name:         "env var set to invalid value",
			key:          "TEST_BOOL_INVALID",
			defaultValue: true,
			envValue:     "invalid",
			setEnv:       true,
			expected:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up after test
			defer func() {
				if tt.setEnv {
					t.Setenv(tt.key, "")
				}
			}()

			if tt.setEnv {
				t.Setenv(tt.key, tt.envValue)
			}

			result := getEnvBool(tt.key, tt.defaultValue)
			if result != tt.expected {
				t.Errorf("getEnvBool(%q, %t) = %t, expected %t", tt.key, tt.defaultValue, result, tt.expected)
			}
		})
	}
}
