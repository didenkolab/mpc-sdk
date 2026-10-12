package mpcdemo

import (
	"fmt"
	"os"
	"strings"
)

// Run executes an example and exits with status 1 if it fails.
func Run(title string, run func() error) {
	fmt.Println(title)
	fmt.Println(strings.Repeat("=", len(title)))
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "\nFAILED: %v\n", err)
		os.Exit(1)
	}
}

// Step prints a numbered section heading.
func Step(n int, title string) {
	fmt.Printf("\n%d. %s\n", n, title)
}

// Field prints an aligned label/value pair.
func Field(label string, value any) {
	fmt.Printf("   %-20s %v\n", label, value)
}

// Done prints the final success line.
func Done(msg string) {
	fmt.Printf("\nOK: %s\n", msg)
}
