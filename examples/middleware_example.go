package main

import (
	"fmt"
)

func tokenValidationMiddlewareExample() {
	fmt.Println("=== Token Validation Middleware Example ===")
	fmt.Println("// Example of how to implement a token validation middleware")
	fmt.Println(`
func AuthMiddleware(maker gourdiantoken.GourdianTokenMaker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract token from Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || len(strings.Split(authHeader, " ")) != 2 {
				http.Error(w, "Unauthorized: Missing or invalid Authorization header", http.StatusUnauthorized)
				return
			}

			tokenString := strings.Split(authHeader, " ")[1]
			
			// Verify the access token
			claims, err := maker.VerifyAccessToken(tokenString)
			if err != nil {
				http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
				return
			}
			
			// Add claims to request context for use in handlers
			ctx := context.WithValue(r.Context(), "user_id", claims.Subject)
			ctx = context.WithValue(ctx, "username", claims.Username)
			ctx = context.WithValue(ctx, "role", claims.Role)
			ctx = context.WithValue(ctx, "permissions", claims.Permissions)
			
			// Continue with the next handler
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}`)
}
