package main

import (
    "fmt"
    "math/rand"
    "strings"
    "time"

    "github.com/pocketbase/pocketbase"
    "github.com/pocketbase/pocketbase/core"
)

func getPBUser(app *pocketbase.PocketBase, userID string, email string) (*core.Record, error) {
	// Try to find existing user by email
    user, err := app.FindAuthRecordByEmail("users", email)
	if err == nil {
        // Update user_id if not set (using Supabase ID)
        if user.GetString("user_id") == "" {
            user.Set("user_id", userID)
            app.Save(user)
        }
        // Ensure existing user is verified
        if !user.GetBool("verified") {
            user.Set("verified", true)
            app.Save(user)
        }
        return user, nil
    }

    // User not found, create new one
    collection, err := app.FindCollectionByNameOrId("users")
    if err != nil {
        return nil, fmt.Errorf("failed to find users collection: %v", err)
    }

    user = core.NewRecord(collection)
    
    username := strings.Split(email, "@")[0]
    password := generateRandomString(12)

    user.Set("email", email)
    user.Set("username", username)
    user.Set("password", password)
    user.Set("user_id", userID)        // Set user_id to Supabase ID
    user.Set("verified", true)         // Set email as verified
    user.Set("emailVisibility", true)  // Make email visible (optional)

    if err := app.Save(user); err != nil {
        return nil, fmt.Errorf("failed to save user: %v", err)
    }

    return user, nil
}

func generateRandomString(length int) string {
    rand.Seed(time.Now().UnixNano())
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    b := make([]byte, length)
    for i := range b {
        b[i] = charset[rand.Intn(len(charset))]
    }
    return string(b)
}
