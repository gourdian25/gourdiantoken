// examples/main.go
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println("GourdianToken Examples")
	fmt.Println("=====================")
	fmt.Println("Choose an example to run:")
	fmt.Println("1. Symmetric Key (HMAC) Example")
	fmt.Println("2. Asymmetric Key (RSA) Example")
	fmt.Println("3. Token Refresh Flow Example")
	fmt.Println("4. Default Configuration Example")
	fmt.Println("5. Run All Examples")
	fmt.Print("Enter your choice (1-5): ")

	var choice int
	_, err := fmt.Scan(&choice)
	if err != nil {
		fmt.Println("Invalid input")
		os.Exit(1)
	}

	switch choice {
	case 1:
		symmetricExample()
	case 2:
		asymmetricExample()
	case 3:
		refreshTokenExample()
	case 4:
		defaultUsageExample()
	case 5:
		symmetricExample()
		asymmetricExample()
		refreshTokenExample()
		defaultUsageExample()
	default:
		fmt.Println("Invalid choice")
		os.Exit(1)
	}

	fmt.Println("\nAll examples completed successfully!")
}
