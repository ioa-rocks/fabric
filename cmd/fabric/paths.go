package main

import (
	"errors"
	"os"
	"path/filepath"

	astraldaemon "ioa.rocks/fabric/astral/daemon"
	"ioa.rocks/fabric/state"
	vaultdaemon "ioa.rocks/fabric/vault/daemon"
	vaultstore "ioa.rocks/fabric/vault/store"
)

// servicePaths lists what `fabric up` with these settings touches outside
// its own binary, as "kind<TAB>path" lines. The service installer builds
// the sandbox from it, so a directory missing here is a directory the
// sandboxed daemon cannot write.
//
//	state   a state directory the daemon owns; it may not exist yet
//	socket  a control socket clients connect to
//	root    a placement's blob store outside the Vault store
//	folder  a folder replica
//	mount   a mountpoint the daemon establishes
//	legacy  a default directory from before the move out of .config,
//	        which the next start renames to its "state" place
//
// It reads declaration files only and starts nothing.
func servicePaths(statePath, vaultState, astralState string, noVault, noAstral bool) ([]string, error) {
	var lines []string
	add := func(kind, path string) { lines = append(lines, kind+"\t"+path) }
	absolute := func(path string) (string, error) { return filepath.Abs(path) }

	statePath, err := absolute(statePath)
	if err != nil {
		return nil, err
	}
	add("state", statePath)
	add("socket", state.Dir{Path: statePath}.ControlSocketPath())

	if !noVault {
		if vaultState, err = absolute(vaultState); err != nil {
			return nil, err
		}
		add("state", vaultState)
		add("socket", vaultdaemon.SocketPath(vaultState))
		if vaultState == vaultstore.DefaultPath() && awaitsMove(vaultState, vaultstore.LegacyPath()) {
			add("legacy", vaultstore.LegacyPath())
		}
		roots, folders, mounts, err := vaultstore.References(vaultstore.ExistingPath(vaultState))
		if err != nil {
			return nil, err
		}
		for _, directory := range roots {
			add("root", directory)
		}
		for _, directory := range folders {
			add("folder", directory)
		}
		for _, directory := range mounts {
			add("mount", directory)
		}
	}

	if !noAstral {
		if astralState, err = absolute(astralState); err != nil {
			return nil, err
		}
		add("state", astralState)
		add("socket", astraldaemon.SocketPath(astralState))
		if astralState == astraldaemon.DefaultPath() && awaitsMove(astralState, astraldaemon.LegacyPath()) {
			add("legacy", astraldaemon.LegacyPath())
		}
	}
	return lines, nil
}

// awaitsMove reports whether a default directory is still at its legacy
// place: the new one is absent and the old one is a directory.
func awaitsMove(current, legacy string) bool {
	if current == legacy {
		return false
	}
	if _, err := os.Lstat(current); !errors.Is(err, os.ErrNotExist) {
		return false
	}
	info, err := os.Lstat(legacy)
	return err == nil && info.IsDir()
}
