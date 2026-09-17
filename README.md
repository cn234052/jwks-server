# JWKS Server

A basic JWKS server implemented in Go for CSCE 3550.

## Features

- Generates RSA key pairs with unique Key IDs (`kid`)
- Supports key expiration
- Serves valid public keys through `/.well-known/jwks.json`
- Provides a `POST /auth` endpoint that returns a signed JWT
- Supports the `expired` query parameter for issuing an expired JWT
- Runs on port 8080

## Run the Server

```bash
go run main.go
