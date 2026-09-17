package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Key struct {
	PrivateKey *rsa.PrivateKey
	Kid        string
	ExpiresAt  time.Time
}

var validKey Key
var expiredKey Key

// generateKey creates an RSA key with a unique kid and expiration time.
func generateKey(kid string, expiresAt time.Time) Key {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	return Key{
		PrivateKey: privateKey,
		Kid:        kid,
		ExpiresAt:  expiresAt,
	}
}

// base64URL converts RSA values into JWK-compatible Base64URL strings.
func base64URL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// jwksHandler returns only public keys that have not expired.
func jwksHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	type JWK struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		Use string `json:"use"`
		Alg string `json:"alg"`
		N   string `json:"n"`
		E   string `json:"e"`
	}

	keys := []JWK{}

	if time.Now().Before(validKey.ExpiresAt) {
		publicKey := validKey.PrivateKey.PublicKey

		n := base64URL(publicKey.N.Bytes())
		eBytes := big.NewInt(int64(publicKey.E)).Bytes()
		e := base64URL(eBytes)

		keys = append(keys, JWK{
			Kty: "RSA",
			Kid: validKey.Kid,
			Use: "sig",
			Alg: "RS256",
			N:   n,
			E:   e,
		})
	}

	response := map[string]interface{}{
		"keys": keys,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// authHandler issues a signed JWT.
// If ?expired is present, it uses the expired key and expiration.
func authHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	key := validKey
	expiration := time.Now().Add(time.Hour)

	if _, exists := r.URL.Query()["expired"]; exists {
		key = expiredKey
		expiration = time.Now().Add(-time.Hour)
	}

	claims := jwt.MapClaims{
		"sub": "fake-user",
		"iat": time.Now().Unix(),
		"exp": expiration.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = key.Kid

	signedToken, err := token.SignedString(key.PrivateKey)
	if err != nil {
		http.Error(w, "Could not create token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/jwt")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(signedToken))
}

// setupRoutes registers the server endpoints.
func setupRoutes() {
	http.HandleFunc("/.well-known/jwks.json", jwksHandler)
	http.HandleFunc("/auth", authHandler)
}

// initializeKeys creates one valid key and one expired key.
func initializeKeys() {
	validKey = generateKey(
		"valid-key",
		time.Now().Add(24*time.Hour),
	)

	expiredKey = generateKey(
		"expired-key",
		time.Now().Add(-24*time.Hour),
	)
}

func main() {
	initializeKeys()
	setupRoutes()

	log.Println("JWKS server running on port 8080")

	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
