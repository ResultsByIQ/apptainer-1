// Copyright (c) 2021 Apptainer a Series of LF Projects LLC
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2020, Control Command Inc. All rights reserved.
// Copyright (c) 2019-2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE.md file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package cli

import (
	"github.com/apptainer/apptainer/docs"
	"github.com/apptainer/apptainer/pkg/cmdline"
	"github.com/apptainer/apptainer/pkg/sylog"
	"github.com/spf13/cobra"
	"runtime"
)

func init() {
	addCmdInit(func(cmdManager *cmdline.CommandManager) {
		cmdManager.RegisterCmd(deleteImageCmd)
		cmdManager.RegisterFlagForCmd(&deleteForceFlag, deleteImageCmd)
		cmdManager.RegisterFlagForCmd(&deleteImageArchFlag, deleteImageCmd)
		cmdManager.RegisterFlagForCmd(&deleteImageTimeoutFlag, deleteImageCmd)
		cmdManager.RegisterFlagForCmd(&deleteLibraryURIFlag, deleteImageCmd)
		cmdManager.RegisterFlagForCmd(&commonNoHTTPSFlag, deleteImageCmd)
	})
}

var (
	deleteForce     bool
	deleteForceFlag = cmdline.Flag{
		ID:           "deleteForceFlag",
		Value:        &deleteForce,
		DefaultValue: false,
		Name:         "force",
		ShortHand:    "F",
		Usage:        "delete image without confirmation",
		EnvKeys:      []string{"FORCE"},
	}
)

var (
	deleteImageArch     string
	deleteImageArchFlag = cmdline.Flag{
		ID:           "deleteImageArchFlag",
		Value:        &deleteImageArch,
		DefaultValue: runtime.GOARCH,
		Name:         "arch",
		ShortHand:    "A",
		Usage:        "specify requested image arch",
		EnvKeys:      []string{"ARCH"},
	}
)

var (
	deleteImageTimeout     int
	deleteImageTimeoutFlag = cmdline.Flag{
		ID:           "deleteImageTimeoutFlag",
		Value:        &deleteImageTimeout,
		DefaultValue: 15,
		Name:         "timeout",
		ShortHand:    "T",
		Hidden:       true,
		Usage:        "specify delete timeout in seconds",
		EnvKeys:      []string{"TIMEOUT"},
	}
)

var (
	deleteLibraryURI     string
	deleteLibraryURIFlag = cmdline.Flag{
		ID:           "deleteLibraryURIFlag",
		Value:        &deleteLibraryURI,
		DefaultValue: "",
		Name:         "library",
		Usage:        "delete images from the provided library",
		EnvKeys:      []string{"LIBRARY"},
	}
)

var deleteImageCmd = &cobra.Command{
	Use:     docs.DeleteUse,
	Short:   docs.DeleteShort,
	Long:    docs.DeleteLong,
	Example: docs.DeleteExample,
	Args:    cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		sylog.Fatalf("Support for Commercial libraries has been removed")
	},
}
