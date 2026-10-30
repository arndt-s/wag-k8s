package csi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// lifetime reads iat and exp from a JWT without verifying it. The driver only
// uses it to decide when to refresh a grant it wrote itself.
func lifetime(token string) (iat, exp time.Time, err error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return time.Time{}, time.Time{}, errors.New("not a JWT")
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	var c struct {
		Iat int64 `json:"iat"`
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return time.Time{}, time.Time{}, err
	}
	if c.Iat == 0 || c.Exp <= c.Iat {
		return time.Time{}, time.Time{}, errors.New("missing or invalid iat/exp")
	}
	return time.Unix(c.Iat, 0), time.Unix(c.Exp, 0), nil
}

// needsRefresh reports whether the grant at path is missing, unreadable or
// past refreshAt of its lifetime.
func needsRefresh(path string, now time.Time, refreshAt float64) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return true
	}
	iat, exp, err := lifetime(string(b))
	if err != nil {
		return true
	}
	due := iat.Add(time.Duration(float64(exp.Sub(iat)) * refreshAt))
	return !now.Before(due)
}

// writeAtomic writes data to dir/name via a temp file and rename, so readers
// never see a partial grant. gid < 0 leaves ownership alone.
func writeAtomic(dir, name string, data []byte, gid int) error {
	f, err := os.CreateTemp(dir, "."+name+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op after a successful rename
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	mode := os.FileMode(0o444)
	if gid >= 0 {
		if err := os.Chown(tmp, 0, gid); err != nil {
			return fmt.Errorf("chown: %w", err)
		}
		mode = 0o440
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, name))
}
