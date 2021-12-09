// Copyright (c) 2021 Apptainer a Series of LF Projects LLC
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2020, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE.md file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package cache

import (
	"os"
	"testing"

	"github.com/apptainer/apptainer/e2e/internal/e2e"
)

// issue5350 - need to handle the cache being inside a non-accssible directory
// e.g. home directory without perms to access
func (c cacheTests) issue5350(t *testing.T) {
	outerDir, cleanupOuter := e2e.MakeTempDir(t, c.env.TestDir, "issue5350-cache-", "")
	defer e2e.Privileged(cleanupOuter)(t)

	sandboxDir, cleanupSandbox := e2e.MakeTempDir(t, c.env.TestDir, "issue5350-sandbox-", "")
	defer e2e.Privileged(cleanupSandbox)(t)

	imgCacheDir, cleanCache := e2e.MakeCacheDir(t, outerDir)
	defer cleanCache(t)
	c.env.ImgCacheDir = imgCacheDir

	if err := os.Chmod(outerDir, 0o000); err != nil {
		t.Fatalf("Could not chmod 000 cache outer dir: %v", err)
	}

	c.env.RunApptainer(
		t,
		e2e.WithProfile(e2e.UserProfile),
		e2e.WithCommand("build"),
		e2e.WithArgs([]string{"--force", "-s", sandboxDir, "library://alpine:3.11.5"}...),
		e2e.ExpectExit(0),
	)

	// Open up permissions or our cleanup will fail
	if err := os.Chmod(outerDir, 0o755); err != nil {
		t.Fatalf("Could not chmod 755 cache outer dir: %v", err)
	}
}
