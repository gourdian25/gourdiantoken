package main

func main() {
	// Example 1: Using symmetric key configuration (HMAC)
	symmetricExample()

	// Example 2: Using asymmetric key configuration (RSA)
	// Uncomment if you have RSA keys available
	asymmetricExample()

	// Example 3: Token refresh example
	refreshTokenExample()

	defaultUsageExample()
}
