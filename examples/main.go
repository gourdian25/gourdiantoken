// examples/main.go
package main

import (
	"fmt"
	"os"

	"github.com/gourdian25/gourdiantoken/examples/scenarios"
)

func main() {
	fmt.Println("GourdianToken Examples")
	fmt.Println("=====================")
	fmt.Println("Choose an example to run:")
	fmt.Println("1. Symmetric Key (HMAC) Example")
	fmt.Println("2. Asymmetric Key (RSA) Example")
	fmt.Println("3. Token Refresh Flow Example")
	fmt.Println("4. Default Configuration Example")
	fmt.Println("5. Token Revocation Example")
	fmt.Println("6. Multi-Tenant Token Example")
	fmt.Println("7. Token Family Example")
	fmt.Println("8. Custom Claims Example")
	fmt.Println("9. Stateless Token Example")
	fmt.Println("10. Short-Lived Token Example")
	fmt.Println("11. High Security Example")
	fmt.Println("12. Run All Examples")
	fmt.Print("Enter your choice (1-12): ")

	var choice int
	_, err := fmt.Scan(&choice)
	if err != nil {
		fmt.Println("Invalid input")
		os.Exit(1)
	}

	switch choice {
	case 1:
		scenarios.RunSymmetricExample()
	case 2:
		scenarios.RunAsymmetricExample()
	case 3:
		scenarios.RunRefreshFlowExample()
	case 4:
		scenarios.RunDefaultConfigExample()
	case 5:
		scenarios.RunRevocationExample()
	case 6:
		scenarios.RunMultiTenantExample()
	case 7:
		scenarios.RunTokenFamilyExample()
	case 8:
		scenarios.RunCustomClaimsExample()
	case 9:
		scenarios.RunStatelessExample()
	case 10:
		scenarios.RunShortLivedExample()
	case 11:
		scenarios.RunHighSecurityExample()
	case 12:
		runAllExamples()
	default:
		fmt.Println("Invalid choice")
		os.Exit(1)
	}

	fmt.Println("\nExample completed successfully!")
}

func runAllExamples() {
	scenarios.RunSymmetricExample()
	scenarios.RunAsymmetricExample()
	scenarios.RunRefreshFlowExample()
	scenarios.RunDefaultConfigExample()
	scenarios.RunRevocationExample()
	scenarios.RunMultiTenantExample()
	scenarios.RunTokenFamilyExample()
	scenarios.RunCustomClaimsExample()
	scenarios.RunStatelessExample()
	scenarios.RunShortLivedExample()
	scenarios.RunHighSecurityExample()
}
