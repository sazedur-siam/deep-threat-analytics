package strutil

import "strings"

// Title upper-cases the first letter.
func Title(s string) string { return strings.ToUpper(s[:1]) + s[1:] }
