package scanner

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"html"
	"net/url"
	"strings"
)

// Mutate creates deterministic, bounded transport/context variants of a seed.
// It does not claim that a variant is exploitable; scanner response comparison
// and browser verification remain responsible for that decision.
func Mutate(seed, strategy string, count int) ([]string, error) {
	if seed == "" {
		return nil, errors.New("payload is required")
	}
	if len(seed) > 64*1024 {
		return nil, errors.New("payload exceeds 64 KiB")
	}
	if count <= 0 {
		count = 10
	}
	if count > 100 {
		count = 100
	}
	strategy = strings.ToLower(strings.TrimSpace(strategy))
	if strategy == "" {
		strategy = "auto"
	}
	allowed := map[string]bool{"auto": true, "encoding": true, "case": true, "whitespace": true, "boundary": true}
	if !allowed[strategy] {
		return nil, errors.New("unknown mutation strategy")
	}
	encodedJSON, _ := json.Marshal(seed)
	jsonString := strings.TrimSuffix(strings.TrimPrefix(string(encodedJSON), `"`), `"`)
	upperAlternating := []rune(seed)
	for index, char := range upperAlternating {
		if index%2 == 0 {
			upperAlternating[index] = []rune(strings.ToUpper(string(char)))[0]
		}
	}
	groups := map[string][]string{
		"encoding": {
			url.QueryEscape(seed),
			url.QueryEscape(url.QueryEscape(seed)),
			jsonString,
			html.EscapeString(seed),
			base64.StdEncoding.EncodeToString([]byte(seed)),
		},
		"case": {
			strings.ToUpper(seed), strings.ToLower(seed), string(upperAlternating),
		},
		"whitespace": {
			strings.ReplaceAll(seed, " ", "/**/"),
			strings.ReplaceAll(seed, " ", "\t"),
			strings.ReplaceAll(seed, " ", "\n"),
		},
		"boundary": {
			seed + "%00", "%00" + seed, `"` + seed + `"`, `'` + seed + `'`, seed + seed,
		},
	}
	candidates := []string{}
	if strategy == "auto" {
		for _, name := range []string{"encoding", "case", "whitespace", "boundary"} {
			candidates = append(candidates, groups[name]...)
		}
	} else {
		candidates = groups[strategy]
	}
	seen := map[string]bool{seed: true}
	result := make([]string, 0, count)
	for _, candidate := range candidates {
		if candidate == "" || seen[candidate] {
			continue
		}
		seen[candidate] = true
		result = append(result, candidate)
		if len(result) == count {
			break
		}
	}
	return result, nil
}
