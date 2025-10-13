package template

import (
	"net/url"
	"strings"

	"github.com/package-url/packageurl-go"
)

// PatternPart is a function that takes a PURL and vulnerability ID, and returns the corresponding string.
type PatternPart func(purl *packageurl.PackageURL, vulnId string) string

type Pattern struct {
	Template string
	Parts    []PatternPart
}

func (p Pattern) Evaluate(purl *packageurl.PackageURL, vulnId string) string {
	var sb strings.Builder
	for _, part := range p.Parts {
		sb.WriteString(part(purl, vulnId))
	}
	return sb.String()
}

type parseMode int

const (
	modePlainText parseMode = iota
	modeFirstBrace
	modeExprText
	modeCharPrefixFirst
	modeCharPrefix
	modeCharSuffix
	modeCharEnd
	modeSegmentPrefixFirst
	modeSegmentPrefix
	modeSegmentSuffix
	modeSegmentEnd
)

// ParsePattern turns the template pattern into sections that turn the PURL and vulnerability ID into a string.
// This handles the parsing of the pattern as described in the README.md file.
func ParsePattern(p string) Pattern {
	runes := []rune(p)
	l := len(runes)

	parts := make([]PatternPart, 0)
	mode := modePlainText
	partStartPos := 0
	startPos := 0
	endPos := 0

	// While the full parser can be brought into this loop, it's split into smaller
	// sections for clarity.

	for i := range l {
		ch := runes[i]
		switch mode {
		case modePlainText:
			// Plain text
			if ch == '{' {
				if i > partStartPos {
					// Wrap up the packet as a simple string.
					parts = append(parts, mkStringPatternPart(string(runes[partStartPos:i])))
				}
				mode = modeFirstBrace
			}
			// else keep reading
		case modeFirstBrace:
			// Found a '{', and had just inserted a string part.
			if ch == '{' {
				// A `{{` encoded value.  Skip the first `{` by pointing the start position
				// to this character, and set the mode to a plain text.
				mode = modePlainText
				partStartPos = i
			} else if ch >= 'A' && ch <= 'Z' {
				// Start of a {} expression
				mode = modeExprText
				partStartPos = i - 1
			} else {
				// Invalid expression.  Treat as plain text.
				// This includes '{}' (empty) expressions.
				mode = modePlainText
				partStartPos = i - 1
			}
		case modeExprText:
			// Inside a {}, before the first ':' or '@'
			if ch == '}' {
				// Wrap up the packet
				parts = append(parts, parseStraightPatternPart(runes[partStartPos+1:i]))
				mode = modePlainText
				partStartPos = i + 1
			} else if ch == ':' {
				mode = modeCharPrefixFirst
			} else if ch == '@' {
				mode = modeSegmentPrefixFirst
			} else if ch < 'A' || ch > 'Z' {
				// Invalid character.  Treat everything read up to this point as plain text.
				mode = modePlainText
			}
			// else keep reading
		case modeCharPrefixFirst:
			// Inside a {}, the first character after a ':'
			if ch == '-' {
				mode = modeCharSuffix
				startPos = i + 1
			} else if ch >= '0' && ch <= '9' {
				mode = modeCharPrefix
				startPos = i
			} else {
				// Invalid character.  Treat everything read up to this point as plain text.
				mode = modePlainText
			}
		case modeCharPrefix:
			// Inside a {}, after a ':' and before a second ':' or '}'
			if ch == '}' {
				// Wrap up the packet
				parts = append(parts, parsePrefixPatternPart(runes[partStartPos+1:startPos-1], runes[startPos:i]))
				mode = modePlainText
				partStartPos = i + 1
			} else if ch == ':' {
				mode = modeCharEnd
				endPos = i + 1
			} else if ch < '0' || ch > '9' {
				// Invalid character.  Treat everything read up to this point as plain text.
				mode = modePlainText
			}
			// else keep reading
		case modeCharSuffix:
			if ch == '}' {
				// Wrap up the packet
				parts = append(parts, parseSuffixPatternPart(runes[partStartPos+1:startPos-2], runes[startPos:i]))
				mode = modePlainText
				partStartPos = i + 1
			} else if ch < '0' || ch > '9' {
				// Invalid character.  Treat everything read up to this point as plain text.
				mode = modePlainText
			}
		case modeCharEnd:
			// Inside a {}, after a second ':' and before a '}'
			if ch == '}' {
				// Wrap up the packet
				parts = append(parts, parseSubstringPatternPart(runes[partStartPos+1:startPos-1], runes[startPos:i], runes[endPos:i]))
				mode = modePlainText
				partStartPos = i + 1
			} else if ch < '0' || ch > '9' {
				// Invalid character.  Treat everything read up to this point as plain text.
				mode = modePlainText
			}
			// else keep reading
		case modeSegmentPrefixFirst:
			// Inside a {}, the first character after a '@'
			if ch == '-' {
				mode = modeSegmentSuffix
				startPos = i + 1
			} else if ch >= '0' && ch <= '9' {
				mode = modeSegmentPrefix
				startPos = i
			} else {
				// Invalid character.  Treat everything read up to this point as plain text.
				mode = modePlainText
			}
		case modeSegmentPrefix:
			// Inside a {}, a '@' and before a ':' or '}'
			if ch == '}' {
				// Wrap up the packet
				parts = append(parts, parseSegmentPrefixPatternPart(runes[partStartPos+1:startPos-1], runes[startPos:i]))
				mode = modePlainText
				partStartPos = i + 1
			} else if ch == ':' {
				mode = modeSegmentEnd
				endPos = i + 1
			} else if ch < '0' || ch > '9' {
				// Invalid character.  Treat everything read up to this point as plain text.
				mode = modePlainText
			}
			// else keep reading
		case modeSegmentSuffix:
			if ch == '}' {
				// Wrap up the packet
				parts = append(parts, parseSegmentSuffixPatternPart(runes[partStartPos+1:startPos-2], runes[startPos:i]))
				mode = modePlainText
				partStartPos = i + 1
			} else if ch < '0' || ch > '9' {
				// Invalid character.  Treat everything read up to this point as plain text.
				mode = modePlainText
			}
		case modeSegmentEnd:
			// Inside a {}, after a second ':' and before a '}'
			if ch == '}' {
				// Wrap up the packet
				parts = append(parts, parseSegmentSubstringPatternPart(runes[partStartPos+1:startPos-1], runes[startPos:i], runes[endPos:i]))
				mode = modePlainText
				partStartPos = i + 1
			} else if ch < '0' || ch > '9' {
				// Invalid character.  Treat everything read up to this point as plain text.
				mode = modePlainText
			}
			// else keep reading
		}
	}
	if partStartPos < l {
		// Wrap up the packet as a simple string.
		parts = append(parts, mkStringPatternPart(string(runes[partStartPos:l])))
	}

	return Pattern{
		Template: p,
		Parts:    parts,
	}
}

func parseStraightPatternPart(textPart []rune) PatternPart {
	switch extractTextFrom(textPart) {
	case extractVulnId:
		return mkEscapePatternPart(mkVulnPatternPart())
	case extractEnv:
		return mkEscapePatternPart(mkEnvPatternPart())
	case extractName:
		return mkEscapePatternPart(mkNamePatternPart())
	case extractModule:
		return mkEscapePatternPart(mkModulePatternPart())
	case extractVersion:
		return mkEscapePatternPart(mkVersionPatternPart())
	default:
		return mkStringPatternPart(string(textPart))
	}
}

func parsePrefixPatternPart(textPart []rune, countText []rune) PatternPart {
	count, ok := atoi(countText)
	if !ok || count <= 0 {
		// Invalid count; treat as a string.
		return mkStringPatternPart("{" + string(textPart) + ":" + string(countText) + "}")
	}
	switch extractTextFrom(textPart) {
	case extractVulnId:
		return mkEscapePatternPart(mkRunePrefixPatternPart(mkVulnPatternPart(), count))
	case extractEnv:
		return mkEscapePatternPart(mkRunePrefixPatternPart(mkEnvPatternPart(), count))
	case extractName:
		return mkEscapePatternPart(mkRunePrefixPatternPart(mkNamePatternPart(), count))
	case extractModule:
		return mkEscapePatternPart(mkRunePrefixPatternPart(mkModulePatternPart(), count))
	case extractVersion:
		return mkEscapePatternPart(mkRunePrefixPatternPart(mkVersionPatternPart(), count))
	default:
		return mkStringPatternPart(string(textPart))
	}
}

func parseSuffixPatternPart(textPart []rune, countText []rune) PatternPart {
	count, ok := atoi(countText)
	if !ok || count <= 0 {
		// Invalid count; treat as a string.
		return mkStringPatternPart("{" + string(textPart) + ":-" + string(countText) + "}")
	}
	switch extractTextFrom(textPart) {
	case extractVulnId:
		return mkEscapePatternPart(mkRuneSuffixPatternPart(mkVulnPatternPart(), count))
	case extractEnv:
		return mkEscapePatternPart(mkRuneSuffixPatternPart(mkEnvPatternPart(), count))
	case extractName:
		return mkEscapePatternPart(mkRuneSuffixPatternPart(mkNamePatternPart(), count))
	case extractModule:
		return mkEscapePatternPart(mkRuneSuffixPatternPart(mkModulePatternPart(), count))
	case extractVersion:
		return mkEscapePatternPart(mkRuneSuffixPatternPart(mkVersionPatternPart(), count))
	default:
		return mkStringPatternPart(string(textPart))
	}
}

func parseSubstringPatternPart(textPart []rune, startText, endText []rune) PatternPart {
	start, ok := atoi(startText)
	if !ok || start <= 0 {
		// Invalid count; treat as a string.
		return mkStringPatternPart("{" + string(textPart) + ":" + string(startText) + ":" + string(endText) + "}")
	}
	end, ok := atoi(endText)
	if !ok || end <= 0 || start > end {
		// Invalid count; treat as a string.
		return mkStringPatternPart("{" + string(textPart) + ":" + string(startText) + ":" + string(endText) + "}")
	}
	switch extractTextFrom(textPart) {
	case extractVulnId:
		return mkEscapePatternPart(mkRuneSubstringPatternPart(mkVulnPatternPart(), start, end))
	case extractEnv:
		return mkEscapePatternPart(mkRuneSubstringPatternPart(mkEnvPatternPart(), start, end))
	case extractName:
		return mkEscapePatternPart(mkRuneSubstringPatternPart(mkNamePatternPart(), start, end))
	case extractModule:
		return mkEscapePatternPart(mkRuneSubstringPatternPart(mkModulePatternPart(), start, end))
	case extractVersion:
		return mkEscapePatternPart(mkRuneSubstringPatternPart(mkVersionPatternPart(), start, end))
	default:
		return mkStringPatternPart(string(textPart))
	}
}

func parseSegmentPrefixPatternPart(textPart []rune, countText []rune) PatternPart {
	count, ok := atoi(countText)
	if !ok || count <= 0 {
		// Invalid count; treat as a string.
		return mkStringPatternPart("{" + string(textPart) + "@" + string(countText) + "}")
	}
	switch extractTextFrom(textPart) {
	case extractVulnId:
		return mkEscapePatternPart(mkSegmentPrefixPatternPart(mkVulnPatternPart(), count))
	case extractEnv:
		return mkEscapePatternPart(mkSegmentPrefixPatternPart(mkEnvPatternPart(), count))
	case extractName:
		return mkEscapePatternPart(mkSegmentPrefixPatternPart(mkNamePatternPart(), count))
	case extractModule:
		return mkEscapePatternPart(mkSegmentPrefixPatternPart(mkModulePatternPart(), count))
	case extractVersion:
		return mkEscapePatternPart(mkSegmentPrefixPatternPart(mkVersionPatternPart(), count))
	default:
		return mkStringPatternPart(string(textPart))
	}
}

func parseSegmentSuffixPatternPart(textPart []rune, countText []rune) PatternPart {
	count, ok := atoi(countText)
	if !ok || count <= 0 {
		// Invalid count; treat as a string.
		return mkStringPatternPart("{" + string(textPart) + "@-" + string(countText) + "}")
	}
	switch extractTextFrom(textPart) {
	case extractVulnId:
		return mkEscapePatternPart(mkSegmentSuffixPatternPart(mkVulnPatternPart(), count))
	case extractEnv:
		return mkEscapePatternPart(mkSegmentSuffixPatternPart(mkEnvPatternPart(), count))
	case extractName:
		return mkEscapePatternPart(mkSegmentSuffixPatternPart(mkNamePatternPart(), count))
	case extractModule:
		return mkEscapePatternPart(mkSegmentSuffixPatternPart(mkModulePatternPart(), count))
	case extractVersion:
		return mkEscapePatternPart(mkSegmentSuffixPatternPart(mkVersionPatternPart(), count))
	default:
		return mkStringPatternPart(string(textPart))
	}
}

func parseSegmentSubstringPatternPart(textPart []rune, startText, endText []rune) PatternPart {
	start, ok := atoi(startText)
	if !ok || start <= 0 {
		// Invalid count; treat as a string.
		return mkStringPatternPart("{" + string(textPart) + "@" + string(startText) + ":" + string(endText) + "}")
	}
	end, ok := atoi(endText)
	if !ok || end <= 0 || start > end {
		// Invalid count; treat as a string.
		return mkStringPatternPart("{" + string(textPart) + "@" + string(startText) + ":" + string(endText) + "}")
	}
	switch extractTextFrom(textPart) {
	case extractVulnId:
		return mkEscapePatternPart(mkSegmentSubstringPatternPart(mkVulnPatternPart(), start, end))
	case extractEnv:
		return mkEscapePatternPart(mkSegmentSubstringPatternPart(mkEnvPatternPart(), start, end))
	case extractName:
		return mkEscapePatternPart(mkSegmentSubstringPatternPart(mkNamePatternPart(), start, end))
	case extractModule:
		return mkEscapePatternPart(mkSegmentSubstringPatternPart(mkModulePatternPart(), start, end))
	case extractVersion:
		return mkEscapePatternPart(mkSegmentSubstringPatternPart(mkVersionPatternPart(), start, end))
	default:
		return mkStringPatternPart(string(textPart))
	}
}

type extractType int

const (
	extractNone extractType = iota
	extractVulnId
	extractEnv
	extractModule
	extractName
	extractVersion
)

func extractTextFrom(runes []rune) extractType {
	text := string(runes)
	switch text {
	case "ENVIRON":
		return extractEnv
	case "MODULE":
		return extractModule
	case "NAME":
		return extractName
	case "VERSION":
		return extractVersion
	case "VULN":
		return extractVulnId
	default:
		return extractNone
	}
}

func mkStringPatternPart(s string) PatternPart {
	return func(purl *packageurl.PackageURL, vulnId string) string {
		return s
	}
}

func mkEscapePatternPart(p PatternPart) PatternPart {
	return func(purl *packageurl.PackageURL, vulnId string) string {
		s := p(purl, vulnId)
		return url.QueryEscape(s)
	}
}

func mkVulnPatternPart() PatternPart {
	return func(purl *packageurl.PackageURL, vulnId string) string {
		return vulnId
	}
}

func mkVersionPatternPart() PatternPart {
	return func(purl *packageurl.PackageURL, vulnId string) string {
		if purl == nil {
			return ""
		}
		return purl.Version
	}
}

func mkModulePatternPart() PatternPart {
	return func(purl *packageurl.PackageURL, vulnId string) string {
		if purl == nil {
			return ""
		}
		return purl.Namespace
	}
}

func mkNamePatternPart() PatternPart {
	return func(purl *packageurl.PackageURL, vulnId string) string {
		if purl == nil {
			return ""
		}
		return purl.Name
	}
}

func mkEnvPatternPart() PatternPart {
	return func(purl *packageurl.PackageURL, vulnId string) string {
		if purl == nil {
			return ""
		}
		return purl.Type
	}
}

func mkRunePrefixPatternPart(part PatternPart, count int) PatternPart {
	return func(purl *packageurl.PackageURL, vulnId string) string {
		s := part(purl, vulnId)
		if len(s) < count {
			return s
		}
		return s[:count]
	}
}

func mkRuneSuffixPatternPart(part PatternPart, count int) PatternPart {
	return func(purl *packageurl.PackageURL, vulnId string) string {
		s := part(purl, vulnId)
		if len(s) < count {
			return s
		}
		return s[len(s)-count:]
	}
}

func mkRuneSubstringPatternPart(part PatternPart, start, end int) PatternPart {
	start = start - 1
	return func(purl *packageurl.PackageURL, vulnId string) string {
		s := part(purl, vulnId)
		c := len(s)
		if c < start {
			return ""
		}
		if len(s) < end {
			return s[start:]
		}
		return s[start:end]
	}
}

func mkSegmentPrefixPatternPart(part PatternPart, count int) PatternPart {
	count = count*2 - 1
	return func(purl *packageurl.PackageURL, vulnId string) string {
		orig := part(purl, vulnId)
		s := splitSegments(orig)
		if len(s) < count {
			return orig
		}
		return strings.Join(s[:count], "")
	}
}

func mkSegmentSuffixPatternPart(part PatternPart, count int) PatternPart {
	count = (count-1)*2 + 1
	return func(purl *packageurl.PackageURL, vulnId string) string {
		orig := part(purl, vulnId)
		s := splitSegments(orig)
		if len(s) < count {
			return orig
		}
		return strings.Join(s[len(s)-count:], "")
	}
}

func mkSegmentSubstringPatternPart(part PatternPart, start, end int) PatternPart {
	// Segments are doubles, so this needs to take care of fence post errors.
	start = (start - 1) * 2
	end = end*2 - 1
	return func(purl *packageurl.PackageURL, vulnId string) string {
		orig := part(purl, vulnId)
		s := splitSegments(orig)
		c := len(s)
		if start > c {
			return ""
		}
		if start == c {
			return s[c-1]
		}
		return strings.Join(s[start:min(end, c)], "")
	}
}

// mkSegmentPatternPart creates a PatternPart that extracts segments from the
// given part.  A segment is defined as a portion of the string separated by
// one or more characters from the set `.-_,:/@`.  This returns
// ("segment" "separators", "segment", ...).
func splitSegments(ver string) []string {
	segments := make([]string, 0)
	wasDiv := false
	start := 0
	for i, c := range ver {
		if c == '.' || c == '-' || c == '_' || c == ',' || c == ':' || c == '/' || c == '@' {
			if wasDiv {
				// Skip repeated dividers
				continue
			} else {
				if i > start {
					segments = append(segments, ver[start:i])
				}
				start = i
			}
			wasDiv = true
		} else {
			if wasDiv {
				segments = append(segments, ver[start:i])
				start = i

			}
			wasDiv = false
		}
	}
	if start < len(ver) {
		segments = append(segments, ver[start:])
	}
	return segments
}

func atoi(runes []rune) (int, bool) {
	n := 0
	found := false
	for _, r := range runes {
		if r < '0' || r > '9' {
			return 0, false
		}
		found = true
		n = n*10 + int(r-'0')
	}
	return n, found
}
