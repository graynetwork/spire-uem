package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// loadState reads the last self-update attempt record. A missing file is not an error
// (returns nil, nil).
func (u *SelfUpdater) loadState() (*updateState, error) {
	if u.statePath == "" {
		return nil, nil
	}
	b, err := os.ReadFile(u.statePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var st updateState
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// saveState writes the self-update attempt record atomically with mode 0600.
func (u *SelfUpdater) saveState(st *updateState) error {
	if u.statePath == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(u.statePath), 0700); err != nil {
		return err
	}
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(u.statePath), ".update-state-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, u.statePath)
}
