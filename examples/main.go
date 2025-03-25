// examples/main.go
package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/gourdian25/gourdiantoken/examples/scenarios"
)

func main() {
	displayMenu()

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("\nEnter your choice (1-16, or 'a' for all): ")

	input, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("Error reading input:", err)
		os.Exit(1)
	}

	input = strings.TrimSpace(input)

	if input == "a" || input == "A" {
		runAllExamples()
		fmt.Println("\nAll examples completed successfully!")
		return
	}

	choice, err := strconv.Atoi(input)
	if err != nil {
		fmt.Println("Invalid input - please enter a number")
		os.Exit(1)
	}

	runExample(choice)
	fmt.Println("\nExample completed successfully!")
}

func displayMenu() {
	fmt.Println(strings.Repeat("=", 40))
	fmt.Println("GourdianToken Examples")
	fmt.Println(strings.Repeat("=", 40))
	fmt.Println("1.  Symmetric Key (HMAC) Example")
	fmt.Println("2.  Asymmetric Key (RSA) Example")
	fmt.Println("3.  Token Refresh Flow Example")
	fmt.Println("4.  Default Configuration Example")
	fmt.Println("5.  Token Revocation Example")
	fmt.Println("6.  Multi-Tenant Token Example")
	fmt.Println("7.  Token Family Example")
	fmt.Println("8.  Custom Claims Example")
	fmt.Println("9.  Stateless Token Example")
	fmt.Println("10. Short-Lived Token Example")
	fmt.Println("11. High Security Example")
	fmt.Println("12. RSA Example")
	fmt.Println("13. RSA-PSS Example")
	fmt.Println("14. EdDSA Example")
	fmt.Println("15. HMAC Example")
	fmt.Println("16. Run All Examples")
}

func runExample(choice int) {
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
		scenarios.RunRSAExample()
	case 13:
		scenarios.RunRSAPSSExample()
	case 14:
		scenarios.RunEdDSAExample()
	case 15:
		scenarios.RunHMACExample()
	case 16:
		runAllExamples()
	default:
		fmt.Println("Invalid choice - please select 1-16")
		os.Exit(1)
	}
}

func runAllExamples() {
	fmt.Println("\nRunning all examples...")
	fmt.Println(strings.Repeat("-", 40))

	examples := []struct {
		name string
		fn   func()
	}{
		{"Symmetric Key (HMAC)", scenarios.RunSymmetricExample},
		{"Asymmetric Key (RSA)", scenarios.RunAsymmetricExample},
		{"Token Refresh Flow", scenarios.RunRefreshFlowExample},
		{"Default Configuration", scenarios.RunDefaultConfigExample},
		{"Token Revocation", scenarios.RunRevocationExample},
		{"Multi-Tenant Token", scenarios.RunMultiTenantExample},
		{"Token Family", scenarios.RunTokenFamilyExample},
		{"Custom Claims", scenarios.RunCustomClaimsExample},
		{"Stateless Token", scenarios.RunStatelessExample},
		{"Short-Lived Token", scenarios.RunShortLivedExample},
		{"High Security", scenarios.RunHighSecurityExample},
		{"RSA", scenarios.RunRSAExample},
		{"RSA-PSS", scenarios.RunRSAPSSExample},
		{"EdDSA", scenarios.RunEdDSAExample},
		{"HMAC", scenarios.RunHMACExample},
	}

	for i, example := range examples {
		fmt.Printf("\n%d. Running %s...\n", i+1, example.name)
		example.fn()
		fmt.Println(strings.Repeat("-", 30))
	}
}
