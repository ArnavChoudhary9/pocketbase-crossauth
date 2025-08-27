package main

import (
    "fmt"  // Add this import
    "log"
    "os"

    "github.com/joho/godotenv"
)

// Config holds all environment variables
type Config struct {
    SupabaseProjectID string
    SupabaseAnonKey   string
    CookieDomain      string
}

// LoadConfig loads environment variables and returns a Config struct
func LoadConfig() *Config {
    err := godotenv.Load()
    if err != nil {
        log.Println("Warning: .env file not found or could not be loaded")
    }

    return &Config{
        SupabaseProjectID: os.Getenv("SUPABASE_PROJECT_ID"),
        SupabaseAnonKey:   os.Getenv("SUPABASE_ANON_KEY"),
        CookieDomain:      os.Getenv("COOKIE_DOMAIN"),
    }
}

// Validate checks if all required environment variables are set
func (c *Config) Validate() error {
    if c.SupabaseProjectID == "" {
        return fmt.Errorf("SUPABASE_PROJECT_ID environment variable is required")
    }
    if c.SupabaseAnonKey == "" {
        return fmt.Errorf("SUPABASE_ANON_KEY environment variable is required")
    }
    return nil
}
