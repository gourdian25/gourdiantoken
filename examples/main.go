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
	fmt.Print("\nEnter your choice (1-14, or 'a' for all): ")

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
	fmt.Println("1.  HMAC Token Demonstration")
	fmt.Println("2.  RSA Token Demonstration")
	fmt.Println("3.  Refresh Token Flow Demonstration")
	fmt.Println("4.  Basic Usage Demonstration")
	fmt.Println("5.  Token Revocation Demonstration")
	fmt.Println("6.  Multi-Tenant Token Demonstration")
	fmt.Println("7.  Token Family Demonstration")
	fmt.Println("8.  Stateless Token Demonstration")
	fmt.Println("9. Short-Lived Token Demonstration")
	fmt.Println("10. High Security Demonstration")
	fmt.Println("11. RSA-PSS Token Demonstration")
	fmt.Println("12. EdDSA Token Demonstration")
	fmt.Println("13. Run All Demonstrations")
}

func runExample(choice int) {
	switch choice {
	case 1:
		scenarios.DemonstrateHMACTokens()
	case 2:
		scenarios.DemonstrateRSATokens()
	case 3:
		scenarios.DemonstrateRefreshFlow()
	case 4:
		scenarios.DemonstrateBasicUsage()
	case 5:
		scenarios.DemonstrateTokenRevocation()
	case 6:
		scenarios.DemonstrateMultiTenant()
	case 7:
		scenarios.DemonstrateTokenFamilies()
	case 8:
		scenarios.DemonstrateStatelessTokens()
	case 9:
		scenarios.DemonstrateShortLivedTokens()
	case 10:
		scenarios.DemonstrateHighSecurity()
	case 11:
		scenarios.DemonstrateRSAPSSTokens()
	case 12:
		scenarios.DemonstrateEdDSATokens()
	case 13:
		runAllExamples()
	default:
		fmt.Println("Invalid choice - please select 1-14")
		os.Exit(1)
	}
}

func runAllExamples() {
	fmt.Println("\nRunning all demonstrations...")
	fmt.Println(strings.Repeat("-", 40))

	examples := []struct {
		name string
		fn   func()
	}{
		{"HMAC Token", scenarios.DemonstrateHMACTokens},
		{"RSA Token", scenarios.DemonstrateRSATokens},
		{"Refresh Token Flow", scenarios.DemonstrateRefreshFlow},
		{"Basic Usage", scenarios.DemonstrateBasicUsage},
		{"Token Revocation", scenarios.DemonstrateTokenRevocation},
		{"Multi-Tenant Token", scenarios.DemonstrateMultiTenant},
		{"Token Family", scenarios.DemonstrateTokenFamilies},
		{"Stateless Token", scenarios.DemonstrateStatelessTokens},
		{"Short-Lived Token", scenarios.DemonstrateShortLivedTokens},
		{"High Security", scenarios.DemonstrateHighSecurity},
		{"RSA-PSS Token", scenarios.DemonstrateRSAPSSTokens},
		{"EdDSA Token", scenarios.DemonstrateEdDSATokens},
	}

	for i, example := range examples {
		fmt.Printf("\n%d. Running %s...\n", i+1, example.name)
		example.fn()
		fmt.Println(strings.Repeat("-", 30))
	}
}
