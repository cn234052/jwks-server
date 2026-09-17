package main

import (
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Create fresh keys before each test.
func setupTestKeys() {
	validKey = generateKey(
		"valid-key",
		time.Now().Add(24*time.Hour),
	)

	expiredKey = generateKey(
		"expired-key",
		time.Now().Add(-24*time.Hour),
	)
}

func TestBase64URL(t *testing.T) {
	result := base64URL([]byte("hello"))

	if result == "" {
		t.Error("base64URL returned an empty string")
	}
}

func TestGenerateKey(t *testing.T) {
	key := generateKey(
		"test-key",
		time.Now().Add(time.Hour),
	)

	if key.PrivateKey == nil {
		t.Error("RSA private key was not generated")
	}

	if key.Kid != "test-key" {
		t.Errorf("Expected kid test-key, got %s", key.Kid)
	}
}

func TestJWKSHandler(t *testing.T) {
	setupTestKeys()

	request := httptest.NewRequest(
		http.MethodGet,
		"/.well-known/jwks.json",
		nil,
	)

	recorder := httptest.NewRecorder()

	jwksHandler(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", recorder.Code)
	}

	var response struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Use string `json:"use"`
			Alg string `json:"alg"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}

	err := json.Unmarshal(recorder.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}

	if len(response.Keys) != 1 {
		t.Fatalf("Expected 1 valid key, got %d", len(response.Keys))
	}

	if response.Keys[0].Kid != "valid-key" {
		t.Errorf(
			"Expected valid-key, got %s",
			response.Keys[0].Kid,
		)
	}

	if response.Keys[0].Kty != "RSA" {
		t.Error("Expected RSA key")
	}

	if response.Keys[0].Alg != "RS256" {
		t.Error("Expected RS256 algorithm")
	}

	if response.Keys[0].Use != "sig" {
		t.Error("Expected key use to be sig")
	}

	if response.Keys[0].N == "" {
		t.Error("Expected RSA modulus")
	}

	if response.Keys[0].E == "" {
		t.Error("Expected RSA exponent")
	}
}

func TestJWKSRejectsPOST(t *testing.T) {
	setupTestKeys()

	request := httptest.NewRequest(
		http.MethodPost,
		"/.well-known/jwks.json",
		nil,
	)

	recorder := httptest.NewRecorder()

	jwksHandler(recorder, request)

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Errorf(
			"Expected status 405, got %d",
			recorder.Code,
		)
	}
}

func TestJWKSWithExpiredValidKey(t *testing.T) {
	validKey = generateKey(
		"valid-key",
		time.Now().Add(-time.Hour),
	)

	request := httptest.NewRequest(
		http.MethodGet,
		"/.well-known/jwks.json",
		nil,
	)

	recorder := httptest.NewRecorder()

	jwksHandler(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", recorder.Code)
	}

	var response struct {
		Keys []interface{} `json:"keys"`
	}

	err := json.Unmarshal(recorder.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}

	if len(response.Keys) != 0 {
		t.Errorf(
			"Expected no expired keys, got %d",
			len(response.Keys),
		)
	}
}

func TestAuthHandler(t *testing.T) {
	setupTestKeys()

	request := httptest.NewRequest(
		http.MethodPost,
		"/auth",
		nil,
	)

	recorder := httptest.NewRecorder()

	authHandler(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", recorder.Code)
	}

	tokenString := strings.TrimSpace(recorder.Body.String())

	token, err := jwt.Parse(
		tokenString,
		func(token *jwt.Token) (interface{}, error) {
			return &validKey.PrivateKey.PublicKey, nil
		},
	)

	if err != nil {
		t.Fatal(err)
	}

	if !token.Valid {
		t.Error("Expected valid JWT")
	}

	if token.Header["kid"] != "valid-key" {
		t.Errorf(
			"Expected valid-key kid, got %v",
			token.Header["kid"],
		)
	}
}

func TestExpiredAuth(t *testing.T) {
	setupTestKeys()

	request := httptest.NewRequest(
		http.MethodPost,
		"/auth?expired=true",
		nil,
	)

	recorder := httptest.NewRecorder()

	authHandler(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", recorder.Code)
	}

	tokenString := strings.TrimSpace(recorder.Body.String())

	parser := jwt.NewParser(
		jwt.WithoutClaimsValidation(),
	)

	token, err := parser.Parse(
		tokenString,
		func(token *jwt.Token) (interface{}, error) {
			return &expiredKey.PrivateKey.PublicKey, nil
		},
	)

	if err != nil {
		t.Fatal(err)
	}

	if token.Header["kid"] != "expired-key" {
		t.Errorf(
			"Expected expired-key kid, got %v",
			token.Header["kid"],
		)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("Could not read JWT claims")
	}

	exp, err := claims.GetExpirationTime()
	if err != nil {
		t.Fatal(err)
	}

	if exp == nil {
		t.Fatal("Expected expiration claim")
	}

	if exp.Time.After(time.Now()) {
		t.Error("Expected JWT to be expired")
	}
}

func TestAuthRejectsGET(t *testing.T) {
	setupTestKeys()

	request := httptest.NewRequest(
		http.MethodGet,
		"/auth",
		nil,
	)

	recorder := httptest.NewRecorder()

	authHandler(recorder, request)

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Errorf(
			"Expected status 405, got %d",
			recorder.Code,
		)
	}
}

func TestRSAKey(t *testing.T) {
	setupTestKeys()

	var key interface{} = validKey.PrivateKey

	if _, ok := key.(*rsa.PrivateKey); !ok {
		t.Error("Expected RSA private key")
	}
}

func TestSetupRoutes(t *testing.T) {
	setupTestKeys()

	oldMux := http.DefaultServeMux
	http.DefaultServeMux = http.NewServeMux()

	defer func() {
		http.DefaultServeMux = oldMux
	}()

	setupRoutes()

	request := httptest.NewRequest(
		http.MethodGet,
		"/.well-known/jwks.json",
		nil,
	)

	recorder := httptest.NewRecorder()

	http.DefaultServeMux.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", recorder.Code)
	}
}
func TestInitializeKeys(t *testing.T) {
	initializeKeys()

	if validKey.PrivateKey == nil {
		t.Error("Valid key was not initialized")
	}

	if expiredKey.PrivateKey == nil {
		t.Error("Expired key was not initialized")
	}

	if validKey.Kid != "valid-key" {
		t.Errorf("Expected valid-key, got %s", validKey.Kid)
	}

	if expiredKey.Kid != "expired-key" {
		t.Errorf("Expected expired-key, got %s", expiredKey.Kid)
	}

	if !validKey.ExpiresAt.After(time.Now()) {
		t.Error("Valid key should not be expired")
	}

	if !expiredKey.ExpiresAt.Before(time.Now()) {
		t.Error("Expired key should be expired")
	}
}
