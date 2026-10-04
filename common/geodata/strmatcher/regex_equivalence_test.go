package strmatcher_test

import (
	"regexp"
	"testing"

	"github.com/eugene/bypasscore/common/geodata/strmatcher"
)

func FuzzRegexMatcherEquivalence(f *testing.F) {
	for _, seed := range [][2]string{
		{`foo.*bar`, "fooxbar"}, {`(?i)foo`, "FOO"}, {`a(?:b|c)+d`, "acbd"},
		{`(?:foo)?bar`, "bar"}, {`\x{FFFD}foo`, "\xfffoo"}, {`(?:abc){2}`, "abcabc"},
	} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, pattern, input string) {
		if len(pattern) > 1024 || len(input) > 4096 {
			return
		}
		standard, err := regexp.Compile(pattern)
		if err != nil {
			return
		}
		optimized, err := strmatcher.Regex.New(pattern)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := optimized.Match(input), standard.MatchString(input); got != want {
			t.Fatalf("pattern=%q input=%q: got %v, want %v", pattern, input, got, want)
		}
	})
}
