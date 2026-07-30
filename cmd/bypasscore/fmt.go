package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"

	"github.com/eugene/bypasscore/common/errors"
)

// formatConfig normalizes a config file to canonical two-space-indented JSON.
// Key order and values are preserved exactly; only whitespace is rewritten.
// The input is checked for duplicate object keys with the same strictness as
// the runtime config loader. When write is true the file is updated in place
// (preserving its permission bits); otherwise the result goes to out.
func formatConfig(path string, write bool, out io.Writer) error {
	raw, err := readConfigFile(path)
	if err != nil {
		return errors.New("format config: ").Base(err)
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return errors.New("format config: ").Base(err)
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		return errors.New("format config: ").Base(err)
	}
	formatted := buf.Bytes()
	if len(formatted) == 0 || formatted[len(formatted)-1] != '\n' {
		formatted = append(formatted, '\n')
	}
	if !write {
		_, err := out.Write(formatted)
		return err
	}
	mode := os.FileMode(0o644)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	if err := os.WriteFile(path, formatted, mode); err != nil {
		return errors.New("format config: write ", path).Base(err)
	}
	return nil
}

func readConfigFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxConfigBytes {
		return nil, errors.New("config exceeds 16 MiB")
	}
	return raw, nil
}
