// Package folder implements the folder replica (file-sync-fuse memo
// "folder-replica"): a bucket placed as a real directory, where the working
// file is the content, plus a scan database and a shadow store beside it.
package folder

import (
	"path"
	"strings"
)

// Ignore is a gitignore-style matcher over bucket policy patterns: a pattern
// containing "/" is anchored at the folder root, one without matches a base
// name at any depth; a trailing "/" matches directories only; "*" matches
// within one path segment and "**" across segments.
type Ignore struct {
	rules []rule
}

type rule struct {
	pattern  string
	anchored bool
	dirOnly  bool
}

// DefaultIgnore is applied to every folder bucket beneath its policy patterns.
var DefaultIgnore = []string{".vault-folder", "node_modules/", ".venv/", "__pycache__/", ".DS_Store", "Thumbs.db"}

func NewIgnore(patterns []string) *Ignore {
	ig := &Ignore{}
	for _, pat := range append(append([]string(nil), DefaultIgnore...), patterns...) {
		pat = strings.TrimSpace(pat)
		if pat == "" || strings.HasPrefix(pat, "#") {
			continue
		}
		item := rule{}
		if strings.HasSuffix(pat, "/") {
			item.dirOnly = true
			pat = strings.TrimSuffix(pat, "/")
		}
		if strings.HasPrefix(pat, "/") {
			item.anchored = true
			pat = strings.TrimPrefix(pat, "/")
		} else if strings.Contains(pat, "/") {
			item.anchored = true
		}
		item.pattern = pat
		ig.rules = append(ig.rules, item)
	}
	return ig
}

// Match reports whether the relative path (forward slashes, no leading
// slash) is ignored. isDir says whether it names a directory; an ignored
// directory ignores everything beneath it.
func (ig *Ignore) Match(rel string, isDir bool) bool {
	if ig == nil {
		return false
	}
	for _, item := range ig.rules {
		if item.dirOnly && !isDir {
			// A dir-only rule still covers files beneath a matching directory.
			if matchesParent(item, rel) {
				return true
			}
			continue
		}
		if item.anchored {
			if globMatch(item.pattern, rel) || matchesParent(item, rel) {
				return true
			}
			continue
		}
		if globMatch(item.pattern, path.Base(rel)) || matchesParent(item, rel) {
			return true
		}
	}
	return false
}

// matchesParent reports whether any proper ancestor directory of rel
// matches the rule.
func matchesParent(item rule, rel string) bool {
	parts := strings.Split(rel, "/")
	for i := 1; i < len(parts); i++ {
		dir := strings.Join(parts[:i], "/")
		if item.anchored {
			if globMatch(item.pattern, dir) {
				return true
			}
		} else if globMatch(item.pattern, parts[i-1]) {
			return true
		}
	}
	return false
}

// globMatch matches pattern against name with "*" within a segment, "?" one
// character and "**" across segments.
func globMatch(pattern, name string) bool {
	if !strings.Contains(pattern, "**") {
		ok, err := path.Match(pattern, name)
		return err == nil && ok
	}
	// Split on the first "**" and try every split point of name.
	head, tail, _ := strings.Cut(pattern, "**")
	tail = strings.TrimPrefix(tail, "/")
	if head != "" {
		head = strings.TrimSuffix(head, "/")
		// name must start with a head match on whole segments.
		np := strings.Split(name, "/")
		hp := strings.Split(head, "/")
		if len(np) < len(hp) {
			return false
		}
		for i := range hp {
			if ok, _ := path.Match(hp[i], np[i]); !ok {
				return false
			}
		}
		name = strings.Join(np[len(hp):], "/")
	}
	if tail == "" {
		return true
	}
	segs := strings.Split(name, "/")
	for i := 0; i <= len(segs); i++ {
		if globMatch(tail, strings.Join(segs[i:], "/")) {
			return true
		}
	}
	return false
}
