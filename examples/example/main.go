package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	"github.com/nscuro/ossindex-client"
)

func main() {
	var (
		username    string
		token       string
		coordinates string
	)

	flag.StringVar(&username, "username", "", "OSS Index username")
	flag.StringVar(&token, "token", "", "OSS Index token")
	flag.StringVar(&coordinates, "coordinates", "", "Coordinates to check")
	flag.Parse()

	var (
		client *ossindex.Client
		err    error
	)

	if username != "" && token != "" {
		client, err = ossindex.NewClient(ossindex.WithAuthentication(username, token))
	} else {
		client, err = ossindex.NewClient()
	}

	if err != nil {
		log.Fatalf("failed to initialize client: %v", err)
	}

	reports, err := client.GetComponentReports(context.Background(), []string{coordinates})
	if err != nil {
		log.Fatalf("failed to get component reports: %v", err)
	}

	fmt.Println()
	for _, report := range reports {
		fmt.Printf(" > %s\n", report.Coordinates)

		if len(report.Vulnerabilities) == 0 {
			fmt.Println("   No Vulnerabilities!")
		} else {
			for _, vulnerability := range report.Vulnerabilities {
				fmt.Printf("   - %s\n", vulnerability.Title)
			}
		}

		fmt.Println()
	}
}
