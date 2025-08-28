package main

import (
    "encoding/base64"
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "regexp"
    "strings"

    "github.com/golang-jwt/jwt/v5"
    "github.com/pocketbase/pocketbase"
    "github.com/pocketbase/pocketbase/core"
)

func main() {
    // Load configuration
    config := LoadConfig()
    if err := config.Validate(); err != nil {
        log.Fatal(err)
    }
    
    app := pocketbase.New()

    app.OnServe().BindFunc(func(se *core.ServeEvent) error {
        // Supabase auth endpoint
        se.Router.POST("/auth", func(e *core.RequestEvent) error {
            return handleSupabaseAuth(e, app)
        })

        // example route to test
        se.Router.GET("/whoami", func(e *core.RequestEvent) error {
            if authed := e.Get("authed"); authed != nil && authed.(bool) {
                pbUser := e.Get("pb_auth_record").(*core.Record)
                claims := e.Get("pb_auth_claims").(jwt.MapClaims)
                
                return e.JSON(http.StatusOK, map[string]interface{}{
                    "authed": true,
                    "user": map[string]interface{}{
                        "pb_id":           pbUser.Id,
                        "supabase_id":     claims["sub"],
                        "email":           claims["email"],
                        "username":        pbUser.GetString("username"),
                        "verified":        pbUser.GetBool("verified"),
                        "emailVisibility": pbUser.GetBool("emailVisibility"),
                    },
                    "claims": map[string]interface{}{
                        "aud":    claims["aud"],
                        "exp":    claims["exp"],
                        "iat":    claims["iat"],
                        "iss":    claims["iss"],
                        "sub":    claims["sub"],
                        "email":  claims["email"],
                        "role":   claims["role"],
                    },
                })
            }

            return e.JSON(http.StatusOK, map[string]interface{}{
                "authed": false,
                "message": "No authentication found",
            })
        })

        // register a global middleware
        se.Router.BindFunc(func(e *core.RequestEvent) error {
            // Define excluded path patterns that should bypass authentication
            excludedPatterns := []string{
                `^/_.*`,         // Admin UI paths (/_/*)
                `^/favicon\.ico$`, // Favicon
                `^/robots\.txt$`,  // Robots.txt (optional)
            }

            p := e.Request.URL.Path

            // Check if path matches any excluded pattern
            for _, pattern := range excludedPatterns {
                matched, err := regexp.MatchString(pattern, p)
                if err != nil {
                    log.Printf("Error matching pattern %s: %v", pattern, err)
                    continue
                }
                if matched {
                    // log.Printf("Skipping auth for excluded path: %s (pattern: %s)", p, pattern)
                    return e.Next()
                }
            }

            jwksUrl := fmt.Sprintf("https://%s.supabase.co/auth/v1/.well-known/jwks.json", config.SupabaseProjectID)
            authTokenName := fmt.Sprintf("sb-%s-auth-token", config.SupabaseProjectID)

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
                    // log.Printf("Attempting to refresh access token...")
                    
                    refreshResp, refreshErr := refreshAccessToken(refreshToken, config.SupabaseProjectID, config.SupabaseAnonKey)
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
                    if err := updateAuthCookie(e, tokenData, authTokenName, config.CookieDomain); err != nil {
                        log.Printf("Failed to update auth cookie: %v", err)
                    }
                    
                    // Try verifying the new access token
                    token, err = verifyJWT(refreshResp.AccessToken, jwks)
                    if err != nil {
                        log.Printf("Failed to verify refreshed JWT: %v", err)
                        return e.UnauthorizedError("Invalid refreshed token", nil)
                    }
                    
                    // log.Printf("Successfully refreshed and verified token")
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

            // Create/find PocketBase user
            pbUser, err := getPBUser(app, claims["sub"].(string), claims["email"].(string))
            if err != nil {
                log.Printf("Failed to get PocketBase user: %v", err)
                return e.InternalServerError("Failed to get user", nil)
            }

            // log.Printf("Token verified successfully!")
            // log.Printf("User ID: %v", claims["sub"])
            // log.Printf("Email: %v", claims["email"])

            // Set PocketBase auth context with claims
            e.Set("pb_auth_record", pbUser)       // Store user claims
            e.Set("pb_auth_claims", claims)       // JWT claims for reference
            e.Set("user_id", claims["sub"])       // Supabase user ID
            e.Set("user_email", claims["email"])
            e.Set("pb_user_id", pbUser.Id)        // PocketBase user ID
            e.Set("authed", true)                 // Authenticated flag

            return e.Next()
        })

        return se.Next()
    })

    if err := app.Start(); err != nil {
        log.Fatal(err)
    }
}

// handleSupabaseAuth handles the /auth/supabase endpoint using middleware data
func handleSupabaseAuth(e *core.RequestEvent, app *pocketbase.PocketBase) error {
    // Check if user is authenticated via middleware
    authed := e.Get("authed")
    if authed == nil || !authed.(bool) {
        return e.JSON(http.StatusUnauthorized, map[string]interface{}{
            "error": "authentication required - no valid Supabase session found",
        })
    }

    // Get JWT claims and PB user from middleware
    claims, ok := e.Get("pb_auth_claims").(jwt.MapClaims)
    if !ok {
        return e.JSON(http.StatusUnauthorized, map[string]interface{}{
            "error": "invalid claims",
        })
    }

    pbUser, ok := e.Get("pb_auth_record").(*core.Record)
    if !ok {
        return e.JSON(http.StatusInternalServerError, map[string]interface{}{
            "error": "failed to get user record",
        })
    }

    // Return response with PocketBase token and user info
    return e.JSON(http.StatusOK, map[string]interface{}{
        "record": map[string]interface{}{
            "id":              pbUser.Id,
            "email":           pbUser.Email(),
            "username":        pbUser.GetString("username"),
            "verified":        pbUser.GetBool("verified"),
            "emailVisibility": pbUser.GetBool("emailVisibility"),
            "user_id":         pbUser.GetString("user_id"), // Supabase ID
        },
        "supabase_claims": map[string]interface{}{
            "user_id": claims["sub"],
            "email":   claims["email"],
            "aud":     claims["aud"],
            "exp":     claims["exp"],
            "iss":     claims["iss"],
        },
        "success": true,
    })
}
