// ETC Collector - Active Directory Security Auditing Tool
// Copyright (c) 2025 ETCSec. All rights reserved.
// Licensed under Apache-2.0

package main

import (
	"os"
)

// Version is set at build time
var Version = "2.0.0-dev"

func main() {
	if err := Execute(); err != nil {
		os.Exit(1)
	}
}
