package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestNoAuthHeaderProvided(t *testing.T) {
	header := http.Header{}

	_, err := GetAPIKey(header)
	if !errors.Is(err, ErrNoAuthHeaderIncluded) {
		t.Fatal("failed to detect that no auth header exists")
	}
}

func TestMalformedAuthHeader(t *testing.T) {
	badLenHeader := make(http.Header)
	badLenHeader.Set("authorization", "ApiKey")

	badFirstTokenHeader := make(http.Header)
	badFirstTokenHeader.Set("authorization", "ApiBee himom12345")

	headers := []http.Header{
		badLenHeader,
		badFirstTokenHeader,
	}

	for _, header := range headers {
		k, err := GetAPIKey(header)
		if !errors.Is(err, ErrMalformedAuthHeader) {
			t.Logf("auth key: %s", k)
			t.Errorf("%v incorrectly considered valid", header)
		}
	}
}

func TestValidAuthHeader(t *testing.T) {
	var header = make(http.Header)
	header.Set("authorization", "ApiKey")

	got, err := GetAPIKey(header)
	if err != nil {
		t.Fatalf("failed to parse valid auth header: %v", err)
	}
	if got != "himom12345" {
		t.Fatalf("failed to varse valid auth header, got %s want himom12345", got)
	}
}
