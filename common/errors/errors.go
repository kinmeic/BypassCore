// Package errors provides structured error objects with chained causes,
// severity levels, and logging helpers. Logging is routed to the standard
// library log package.
package errors // import "github.com/eugene/bypasscore/common/errors"

import (
	"context"
	"fmt"
	"log"
	"runtime"
	"strings"
)

// trim is the prefix length used to shorten caller names. Callers are reported
// as their package name only (trimmed at the first dot).
func callerName(skip int) string {
	pc, _, _, ok := runtime.Caller(skip)
	if !ok {
		return ""
	}
	details := runtime.FuncForPC(pc).Name()
	// strip module path if present
	if i := strings.LastIndex(details, "/"); i >= 0 {
		details = details[i+1:]
	}
	if i := strings.Index(details, "."); i > 0 {
		details = details[:i]
	}
	return details
}

// Severity classifies log/error levels. Lower values are more severe
// (Severity_Error = -2).
type Severity int

const (
	Severity_Debug Severity = -4
	Severity_Info  Severity = -3
	Severity_Warning Severity = -2
	Severity_Error Severity = -1
	severity_Print Severity = 0 // never logged through Log* directly
)

func (s Severity) String() string {
	switch s {
	case Severity_Debug:
		return "[Debug]"
	case Severity_Info:
		return "[Info]"
	case Severity_Warning:
		return "[Warning]"
	case Severity_Error:
		return "[Error]"
	default:
		return ""
	}
}

type hasInnerError interface {
	Unwrap() error
}

type hasSeverity interface {
	Severity() Severity
}

// Error is an error object with underlying error.
type Error struct {
	prefix   []interface{}
	message  []interface{}
	caller   string
	inner    error
	severity Severity
}

// Error implements error.Error().
func (err *Error) Error() string {
	var b strings.Builder
	for _, prefix := range err.prefix {
		b.WriteByte('[')
		b.WriteString(toString(prefix))
		b.WriteString("] ")
	}
	if len(err.caller) > 0 {
		b.WriteString(err.caller)
		b.WriteString(": ")
	}
	b.WriteString(concat(err.message...))
	if err.inner != nil {
		b.WriteString(" > ")
		b.WriteString(err.inner.Error())
	}
	return b.String()
}

// Unwrap implements hasInnerError.Unwrap()
func (err *Error) Unwrap() error {
	if err.inner == nil {
		return nil
	}
	return err.inner
}

// Base chains an underlying error.
func (err *Error) Base(e error) *Error {
	err.inner = e
	return err
}

func (err *Error) atSeverity(s Severity) *Error {
	err.severity = s
	return err
}

// Severity returns the effective severity, honoring inner errors.
func (err *Error) Severity() Severity {
	if err.inner == nil {
		return err.severity
	}
	if s, ok := err.inner.(hasSeverity); ok {
		as := s.Severity()
		if as < err.severity {
			return as
		}
	}
	return err.severity
}

// AtDebug sets the severity to debug.
func (err *Error) AtDebug() *Error { return err.atSeverity(Severity_Debug) }

// AtInfo sets the severity to info.
func (err *Error) AtInfo() *Error { return err.atSeverity(Severity_Info) }

// AtWarning sets the severity to warning.
func (err *Error) AtWarning() *Error { return err.atSeverity(Severity_Warning) }

// AtError sets the severity to error.
func (err *Error) AtError() *Error { return err.atSeverity(Severity_Error) }

// String returns the string representation of this error.
func (err *Error) String() string { return err.Error() }

// New returns a new error object with message formed from given arguments.
func New(msg ...interface{}) *Error {
	return &Error{
		message:  msg,
		severity: Severity_Info,
		caller:   callerName(2),
	}
}

// --- Logging helpers ---

func LogDebug(ctx context.Context, msg ...interface{}) {
	doLog(ctx, nil, Severity_Debug, msg...)
}
func LogDebugInner(ctx context.Context, inner error, msg ...interface{}) {
	doLog(ctx, inner, Severity_Debug, msg...)
}
func LogInfo(ctx context.Context, msg ...interface{}) {
	doLog(ctx, nil, Severity_Info, msg...)
}
func LogInfoInner(ctx context.Context, inner error, msg ...interface{}) {
	doLog(ctx, inner, Severity_Info, msg...)
}
func LogWarning(ctx context.Context, msg ...interface{}) {
	doLog(ctx, nil, Severity_Warning, msg...)
}
func LogWarningInner(ctx context.Context, inner error, msg ...interface{}) {
	doLog(ctx, inner, Severity_Warning, msg...)
}
func LogError(ctx context.Context, msg ...interface{}) {
	doLog(ctx, nil, Severity_Error, msg...)
}
func LogErrorInner(ctx context.Context, inner error, msg ...interface{}) {
	doLog(ctx, inner, Severity_Error, msg...)
}

// doLog routes the message to the standard library logger. The severity gates
// output: Debug is suppressed by default to avoid noise.
func doLog(_ context.Context, inner error, severity Severity, msg ...interface{}) {
	if severity < Severity_Debug {
		return // unknown, bail out
	}
	if severity == Severity_Debug {
		// Debug is off by default to keep output clean.
		return
	}
	err := &Error{
		message:  msg,
		severity: severity,
		caller:   callerName(3),
		inner:    inner,
	}
	log.Println(severity.String(), err.Error())
}

// Cause returns the root cause of this error.
func Cause(err error) error {
	if err == nil {
		return nil
	}
	for {
		inner, ok := err.(hasInnerError)
		if !ok || inner.Unwrap() == nil {
			return err
		}
		err = inner.Unwrap()
	}
}

// GetSeverity returns the actual severity of the error, including inner errors.
func GetSeverity(err error) Severity {
	if s, ok := err.(hasSeverity); ok {
		return s.Severity()
	}
	return Severity_Info
}

// --- local formatting helpers (stand-ins for common/serial) ---

func toString(v interface{}) string {
	return fmt.Sprint(v)
}

// concat mirrors serial.Concat: it concatenates the textual form of each arg.
func concat(msg ...interface{}) string {
	return fmt.Sprint(msg...)
}
