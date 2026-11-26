package profile

import (
	"strings"
)

func space(c byte) bool { return c == ' ' || c == '\t' }

// words tokenizes one directive line. Quotes delimit a single argument.
// Backslashes in single quotes are literal.
func words(line string) ([]string, bool) {
	var fields []string
	for len(line) != 0 {
		line = strings.TrimLeft(line, " \t")
		if line == "" || line[0] == '#' || line[0] == ';' {
			break
		}
		value, next, ok := word(line)
		if !ok || len(fields) == maxFields {
			return fields, false
		}
		fields = append(fields, value)
		line = next
	}
	return fields, true
}

func word(line string) (string, string, bool) {
	var quote byte
	if line[0] == '\'' || line[0] == '"' {
		quote = line[0]
		line = line[1:]
	}
	var value strings.Builder
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quote != 0 && c == quote:
			rest := line[i+1:]
			if len(rest) != 0 && !space(rest[0]) && rest[0] != '#' && rest[0] != ';' {
				return "", "", false
			}
			return value.String(), rest, true
		case quote == 0 && space(c):
			return value.String(), line[i:], true
		case quote == 0 && (c == '\'' || c == '"'):
			return "", "", false
		case c == '\\' && quote != '\'':
			i++
			if i == len(line) {
				return "", "", false
			}
			c = line[i]
			if c != '\\' && c != '"' && !space(c) {
				return "", "", false
			}
		}
		value.WriteByte(c)
	}
	return value.String(), "", quote == 0
}
