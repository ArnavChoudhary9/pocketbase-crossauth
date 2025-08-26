package main

import (
    "log"

    "github.com/pocketbase/pocketbase"
    "github.com/pocketbase/pocketbase/core"
)

func main() {
    app := pocketbase.New()

    app.OnServe().BindFunc(func(se *core.ServeEvent) error {
        // register a global middleware
        se.Router.BindFunc(func(e *core.RequestEvent) error {
            // Read all cookies
            cookies := e.Request.Cookies()
            for _, cookie := range cookies {
                log.Printf("Cookie: %s = %s", cookie.Name, cookie.Value)
            }

            return e.Next()
        })

        return se.Next()
    })

    if err := app.Start(); err != nil {
        log.Fatal(err)
    }
}