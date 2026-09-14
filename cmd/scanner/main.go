// iam-policy-scanner: detect overly permissive IAM policies before they reach production.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/TushGoel/iam-policy-scanner/internal/policy"
	"github.com/TushGoel/iam-policy-scanner/internal/report"
)

func main() {
	jsonOutput := flag.Bool("json", false, "output results as JSON")
	sarifOutput := flag.Bool("sarif", false, "output results as SARIF 2.1.0 (for GitHub code scanning)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: iam-policy-scanner [flags] policy.json [policy2.json ...]\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  iam-policy-scanner policy.json\n")
		fmt.Fprintf(os.Stderr, "  iam-policy-scanner --json policies/*.json\n")
		fmt.Fprintf(os.Stderr, "  iam-policy-scanner --sarif policies/*.json\n")
	}
	flag.Parse()

	paths := flag.Args()
	if len(paths) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	v := policy.New()
	result := v.ScanFiles(paths)

	switch {
	case *sarifOutput:
		if err := report.PrintSARIF(os.Stdout, result); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case *jsonOutput:
		if err := report.PrintJSON(os.Stdout, result); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	default:
		report.PrintSummary(os.Stdout, result)
	}

	if result.CriticalCount > 0 || result.HighCount > 0 {
		os.Exit(1) // non-zero exit for CI/CD integration
	}
}
