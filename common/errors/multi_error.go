package errors

import (
	stderrors "errors"
	"strings"
)

type multiError []error

func (e multiError) Error() string {
	var r strings.Builder
	r.WriteString("multierr: ")
	for _, err := range e {
		r.WriteString(err.Error())
		r.WriteString(" | ")
	}
	return r.String()
}

// Combine returns nil if no errors were passed, otherwise a combined error.
func Combine(maybeError ...error) error {
	var errs multiError
	for _, err := range maybeError {
		if err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return errs
}

// AllEqual reports whether actual (possibly a multiError) consists solely of
// errors matching expected via errors.Is.
func AllEqual(expected error, actual error) bool {
	switch errs := actual.(type) {
	case multiError:
		if len(errs) == 0 {
			return false
		}
		for _, err := range errs {
			if !stderrors.Is(err, expected) {
				return false
			}
		}
		return true
	default:
		return stderrors.Is(errs, expected)
	}
}
