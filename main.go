package main

import (
	"os"

	"github.com/calvigil/calvigil/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
