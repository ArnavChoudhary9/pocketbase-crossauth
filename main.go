package main

import (
    "bytes"
    "crypto/ecdsa"
    "crypto/elliptic"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "log"
    "math/big"
    "net/http"
    "os"
    "strings"
    "sync"
    "time"
    "regexp"

    "github.com/golang-jwt/jwt/v5"
    "github.com/joho/godotenv"
    "github.com/pocketbase/pocketbase"
    "github.com/pocketbase/pocketbase/core"
)

// JWKS represents the JSON Web Key Set structure
type JWKS struct {
    Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key
type JWK struct {
    Alg    string   `json:"alg"`             // Algorithm (e.g., "ES256")
    Crv    string   `json:"crv"`             // Curve (e.g., "P-256")
    Ext    bool     `json:"ext"`             // Extractable
    KeyOps []string `json:"key_ops"`         // Key operations (e.g., ["verify"])
    Kid    string   `json:"kid"`             // Key ID
    Kty    string   `json:"kty"`             // Key type (e.g., "EC")
    Use    string   `json:"use"`             // Usage (e.g., "sig")
    X      string   `json:"x"`               // X coordinate for EC keys
    Y      string   `json:"y"`               // Y coordinate for EC keys
    N      string   `json:"n,omitempty"`     // Modulus for RSA keys (optional)
    E      string   `json:"e,omitempty"`     // Exponent for RSA keys (optional)
}

// Cache structure for JWKS
type JWKSCache struct {
    keys      *JWKS
    expiresAt time.Time
    mutex     sync.RWMutex
}

var jwksCache = &JWKSCache{}

// RefreshTokenRequest represents the refresh token request payload
type RefreshTokenRequest struct {
    RefreshToken string `json:"refresh_token"`
}

// RefreshTokenResponse represents the refresh token response
type RefreshTokenResponse struct {
    AccessToken  string `json:"access_token"`
    TokenType    string `json:"token_type"`
    ExpiresIn    int    `json:"expires_in"`
    ExpiresAt    int64  `json:"expires_at"`
    RefreshToken string `json:"refresh_token"`
    User         interface{} `json:"user"`
}

// fetchJWKS fetches JWKS from the given URL with caching
func fetchJWKS(jwksUrl string) (*JWKS, error) {
    jwksCache.mutex.RLock()
    if jwksCache.keys != nil && time.Now().Before(jwksCache.expiresAt) {
        keys := jwksCache.keys
        jwksCache.mutex.RUnlock()
        log.Printf("Using cached JWKS keys")
        return keys, nil
    }
    jwksCache.mutex.RUnlock()

    jwksCache.mutex.Lock()
    defer jwksCache.mutex.Unlock()

    // Double-check after acquiring write lock
    if jwksCache.keys != nil && time.Now().Before(jwksCache.expiresAt) {
        log.Printf("Using cached JWKS keys (double-check)")
        return jwksCache.keys, nil
    }

    log.Printf("Fetching JWKS from: %s", jwksUrl)
    
    client := &http.Client{
        Timeout: 10 * time.Second,
    }
    
    resp, err := client.Get(jwksUrl)
    if err != nil {
        return nil, fmt.Errorf("failed to fetch JWKS: %v", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("JWKS endpoint returned status: %d", resp.StatusCode)
    }

    var jwks JWKS
    if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
        return nil, fmt.Errorf("failed to decode JWKS: %v", err)
    }

    // Cache for 1 hour
    jwksCache.keys = &jwks
    jwksCache.expiresAt = time.Now().Add(1 * time.Hour)
    
    log.Printf("Cached %d JWKS keys", len(jwks.Keys))
    for i, key := range jwks.Keys {
        log.Printf("Key %d: ID=%s, Algorithm=%s, Type=%s, Curve=%s", i, key.Kid, key.Alg, key.Kty, key.Crv)
    }
    
    return &jwks, nil
}

// convertJWKToECDSAPublicKey converts a JWK to an ECDSA public key
func convertJWKToECDSAPublicKey(jwk JWK) (*ecdsa.PublicKey, error) {
    if jwk.Kty != "EC" {
        return nil, fmt.Errorf("key type %s not supported", jwk.Kty)
    }

    var curve elliptic.Curve
    switch jwk.Crv {
    case "P-256":
        curve = elliptic.P256()
    case "P-384":
        curve = elliptic.P384()
    case "P-521":
        curve = elliptic.P521()
    default:
        return nil, fmt.Errorf("curve %s not supported", jwk.Crv)
    }

    xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
    if err != nil {
        return nil, fmt.Errorf("failed to decode x coordinate: %v", err)
    }

    yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
    if err != nil {
        return nil, fmt.Errorf("failed to decode y coordinate: %v", err)
    }

    x := new(big.Int).SetBytes(xBytes)
    y := new(big.Int).SetBytes(yBytes)

    return &ecdsa.PublicKey{
        Curve: curve,
        X:     x,
        Y:     y,
    }, nil
}

// verifyJWT verifies the JWT token against JWKS keys
func verifyJWT(tokenString string, jwks *JWKS) (*jwt.Token, error) {
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        // Check the signing method
        if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }

        // Get the key ID from the token header
        kid, ok := token.Header["kid"].(string)
        if !ok {
            return nil, fmt.Errorf("kid not found in token header")
        }

        // Find the matching key in JWKS
        for _, key := range jwks.Keys {
            if key.Kid == kid {
                return convertJWKToECDSAPublicKey(key)
            }
        }

        return nil, fmt.Errorf("key with id %s not found", kid)
    })

    if err != nil {
        return nil, err
    }

    if !token.Valid {
        return nil, fmt.Errorf("token is not valid")
    }

    return token, nil
}

// refreshAccessToken refreshes the access token using the refresh token
func refreshAccessToken(refreshToken, supabaseProjectId string) (*RefreshTokenResponse, error) {
    refreshUrl := fmt.Sprintf("https://%s.supabase.co/auth/v1/token?grant_type=refresh_token", supabaseProjectId)
    
    reqBody := RefreshTokenRequest{
        RefreshToken: refreshToken,
    }
    
    jsonBody, err := json.Marshal(reqBody)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal request: %v", err)
    }
    
    client := &http.Client{
        Timeout: 10 * time.Second,
    }
    
    req, err := http.NewRequest("POST", refreshUrl, bytes.NewBuffer(jsonBody))
    if err != nil {
        return nil, fmt.Errorf("failed to create request: %v", err)
    }
    
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("apikey", os.Getenv("SUPABASE_ANON_KEY"))
    
    resp, err := client.Do(req)
    if err != nil {
        return nil, fmt.Errorf("failed to refresh token: %v", err)
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("refresh token endpoint returned status: %d", resp.StatusCode)
    }
    
    var refreshResp RefreshTokenResponse
    if err := json.NewDecoder(resp.Body).Decode(&refreshResp); err != nil {
        return nil, fmt.Errorf("failed to decode refresh response: %v", err)
    }
    
    return &refreshResp, nil
}

// updateAuthCookie updates the auth cookie with new token data
func updateAuthCookie(e *core.RequestEvent, newTokenData map[string]interface{}, authTokenName string) error {
    // Encode the new token data to JSON and then base64
    jsonData, err := json.Marshal(newTokenData)
    if err != nil {
        return fmt.Errorf("failed to marshal new token data: %v", err)
    }
    
    encodedData := base64.StdEncoding.EncodeToString(jsonData)
    cookieValue := "base64-" + encodedData
    
    // Set the new cookie
    cookie := &http.Cookie{
        Name:     authTokenName,
        Value:    cookieValue,
        Path:     "/",
        HttpOnly: true,
        Secure:   true, // Set to false for development if using HTTP
        SameSite: http.SameSiteLaxMode,
    }
    
    e.Response.Header().Set("Set-Cookie", cookie.String())
    return nil
}

// upsertPBUser finds or creates a pocketbase auth record with supabase_id
func upsertPBUser(app *pocketbase.PocketBase, supabaseId, email string) (*core.Record, error) {
    dao := app.Dao()
    // attempt to find by supabase_id
    filter := fmt.Sprintf("supabase_id = '%s'", supabaseId)
    records, err := dao.FindRecordsByExpr("users", filter, nil)
    if err == nil && len(records) > 0 {
        return records[0], nil
    }

    // not found -> create
    col, err := dao.FindCollectionByNameOrId("users")
    if err != nil {
        return nil, fmt.Errorf("users collection not found: %w", err)
    }

    rec := core.NewRecord(col)
    rec.Set("supabase_id", supabaseId)
    if email != "" {
        rec.SetEmail(email)
        rec.SetVerified(true)
    }
    // set a random password so PB treats it as an auth record
    rec.SetRandomPassword()

    if err := dao.SaveRecord(rec); err != nil {
        return nil, fmt.Errorf("failed to save user: %w", err)
    }
    return rec, nil
}

func main() {
    err := godotenv.Load()
    if err != nil {
        log.Println("Warning: .env file not found or could not be loaded")
    }
    
    app := pocketbase.New()

    app.OnServe().BindFunc(func(se *core.ServeEvent) error {
        // example route to test
        se.Router.GET("/whoami", func(e *core.RequestEvent) error {
            if r := e.Get("pb_auth_record"); r != nil {
                rec := r.(*core.Record)
                return e.JSON(http.StatusOK, map[string]interface{}{
                    "pb_user_id": rec.Id,
                    "email":      rec.Email(),
                })
            }
            return e.JSON(http.StatusOK, map[string]interface{}{"authed": false})
        })

        // register a global middleware
        se.Router.BindFunc(func(e *core.RequestEvent) error {
            // Allow admin UI paths or assets to bypass (optional)
            var adminPathRegex = regexp.MustCompile(`^/_(/.*)?$`)
            p := e.Request.URL.Path
            if adminPathRegex.MatchString(p) {
                return e.Next()
            }

            supabaseProjectId := os.Getenv("SUPABASE_PROJECT_ID")
            jwksUrl := fmt.Sprintf("https://%s.supabase.co/auth/v1/.well-known/jwks.json", supabaseProjectId)
            authTokenName := fmt.Sprintf("sb-%s-auth-token", supabaseProjectId)

            // Fetch and cache JWKS keys
            jwks, err := fetchJWKS(jwksUrl)
            if err != nil {
                log.Printf("Failed to fetch JWKS: %v", err)
                return e.InternalServerError("JWKS fetch failed", nil)
            }

            // Read auth-token cookie
            authCookie, err := e.Request.Cookie(authTokenName)
            if err != nil {
                log.Printf("Auth token cookie not found: %v", err)
                return e.UnauthorizedError("Authentication required", nil)
            }
            cookieValue := authCookie.Value
            cookieValue = strings.TrimPrefix(cookieValue, "base64-")

            // Decode base64 to bytes
            decodedBytes, err := base64.StdEncoding.DecodeString(cookieValue)
            if err != nil {
                log.Printf("Failed to decode base64: %v", err)
                return e.BadRequestError("Invalid token format", nil)
            }

            // Parse JSON
            var tokenData map[string]interface{}
            err = json.Unmarshal(decodedBytes, &tokenData)
            if err != nil {
                log.Printf("Failed to parse JSON: %v", err)
                return e.BadRequestError("Invalid token JSON", nil)
            }

            accessToken, ok := tokenData["access_token"].(string)
            if !ok {
                log.Printf("Access token not found or invalid type")
                return e.BadRequestError("Invalid access token", nil)
            }

            // Verify the JWT token
            token, err := verifyJWT(accessToken, jwks)
            if err != nil {
                log.Printf("Failed to verify JWT: %v", err)
                
                // Check if we have a refresh token to try refreshing
                if refreshToken, ok := tokenData["refresh_token"].(string); ok && refreshToken != "" {
                    log.Printf("Attempting to refresh access token...")
                    
                    refreshResp, refreshErr := refreshAccessToken(refreshToken, supabaseProjectId)
                    if refreshErr != nil {
                        log.Printf("Failed to refresh token: %v", refreshErr)
                        return e.UnauthorizedError("Token refresh failed", nil)
                    }
                    
                    // Update token data with new values
                    tokenData["access_token"] = refreshResp.AccessToken
                    tokenData["refresh_token"] = refreshResp.RefreshToken
                    tokenData["expires_at"] = refreshResp.ExpiresAt
                    tokenData["user"] = refreshResp.User
                    
                    // Update the cookie with new token data
                    if err := updateAuthCookie(e, tokenData, authTokenName); err != nil {
                        log.Printf("Failed to update auth cookie: %v", err)
                    }
                    
                    // Try verifying the new access token
                    token, err = verifyJWT(refreshResp.AccessToken, jwks)
                    if err != nil {
                        log.Printf("Failed to verify refreshed JWT: %v", err)
                        return e.UnauthorizedError("Invalid refreshed token", nil)
                    }
                    
                    log.Printf("Successfully refreshed and verified token")
                } else {
                    return e.UnauthorizedError("Invalid token and no refresh token available", nil)
                }
            }

            // Extract claims from verified token
            claims, ok := token.Claims.(jwt.MapClaims)
            if !ok {
                log.Printf("Failed to extract claims from token")
                return e.UnauthorizedError("Invalid token claims", nil)
            }

            // Extract id and email
            rec, err := upsertPBUser(app, claims["sub"].(string), claims["email"].(string))
            if err != nil {
                log.Printf("Failed to upsert PocketBase user: %v", err)
                return e.InternalServerError("Failed to upsert user", nil)
            }

            // attach auth to the request context so PB handlers see it
            // context key used by pocketbase for auth is "auth" in RequestEvent; here we set on echo context
            // set the pb auth record and claims for downstream handlers
            e.Set("pb_auth_record", rec)
            e.Set("pb_auth_claims", claims)

            return e.Next()
        })

        return se.Next()
    })

    if err := app.Start(); err != nil {
        log.Fatal(err)
    }
}
