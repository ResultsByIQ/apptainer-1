// Copyright (c) 2021 Apptainer a Series of LF Projects LLC
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2021 Apptainer a Series of LF Projects LLC
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2020, Control Command Inc. All rights reserved.
// Copyright (c) 2019-2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE.md file distributed with the sources of this project regarding your
// rights to use or distribute this software.

// Package syfs provides functions to access apptainer's file system
// layout.
package syfs

import (
	"os"
	"os/user"
	"path/filepath"
	"sync"

	"github.com/apptainer/apptainer/pkg/sylog"
)

// Configuration files/directories.
const (
	RemoteConfFile = "remote.yaml"
	RemoteCache    = "remote-cache"
	DockerConfFile = "docker-config.json"
	apptainerDir   = ".apptainer"
)

// cache contains the information for the current user
var cache struct {
	sync.Once
	configDir string // apptainer user configuration directory
}

// ConfigDir returns the directory where the apptainer user
// configuration and data is located.
func ConfigDir() string {
	cache.Do(func() {
		cache.configDir = configDir()
		sylog.Debugf("Using apptainer directory %q", cache.configDir)
	})

	return cache.configDir
}

func configDir() string {
	user, err := user.Current()
	if err != nil {
		sylog.Warningf("Could not lookup the current user's information: %s", err)

		cwd, err := os.Getwd()
		if err != nil {
			sylog.Warningf("Could not get current working directory: %s", err)
			return apptainerDir
		}

		return filepath.Join(cwd, apptainerDir)
	}

	return filepath.Join(user.HomeDir, apptainerDir)
}

func RemoteConf() string {
	return filepath.Join(ConfigDir(), RemoteConfFile)
}

func RemoteCacheDir() string {
	return filepath.Join(ConfigDir(), RemoteCache)
}

func DockerConf() string {
	return filepath.Join(ConfigDir(), DockerConfFile)
}

// ConfigDirForUsername returns the directory where the apptainer
// configuration and data for the specified username is located.
func ConfigDirForUsername(username string) (string, error) {
	u, err := user.Lookup(username)
	if err != nil {
		return "", err
	}

	if cu, err := user.Current(); err == nil && u.Username == cu.Username {
		return ConfigDir(), nil
	}

	return filepath.Join(u.HomeDir, apptainerDir), nil
}
