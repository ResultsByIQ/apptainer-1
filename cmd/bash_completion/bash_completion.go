// Copyright (c) 2021 Apptainer a Series of LF Projects LLC
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2018-2019, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE.md file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package main

import (
	"fmt"
	"os"

	"github.com/apptainer/apptainer/cmd/internal/cli"
)

func main() {
	fh, err := os.Create(os.Args[1])
	if err != nil {
		fmt.Println(err)
		return
	}

	defer fh.Close()

	if err := cli.GenBashCompletion(fh); err != nil {
		fmt.Println(err)
		return
	}
}
