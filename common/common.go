// Package common contains common utilities shared among other packages.
package common

import (
	"github.com/eugene/bypasscore/common/errors"
)

// ErrNoClue is for the situation that existing information is not enough to
// make a decision. For example, Router returns this error when no rule matches.
var ErrNoClue = errors.New("not enough information for making a decision")

// Must panics if err is not nil.
func Must(err error) {
	if err != nil {
		panic(err)
	}
}

// Must2 panics if the second parameter is not nil, otherwise returns the first.
func Must2[T any](v T, err error) T {
	Must(err)
	return v
}

// Error2 returns the err from the 2nd parameter.
func Error2(v interface{}, err error) error {
	return err
}
