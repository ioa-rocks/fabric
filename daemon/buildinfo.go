package daemon

import (
	"runtime/debug"
	"strings"

	"github.com/libp2p/go-libp2p/core/peer"
)

// Version is the binary's release label; the composition root sets it.
var Version = "0.0.1"

// Agent is the software label this node announces on libp2p identify
// (AgentVersion) and reports for every peer: release, git revision and a
// "+" when the tree was dirty. A rolling upgrade reads off `fabric status`
// which nodes still run the old binary (operator, 2026-11-04).
func Agent() string {
	rev, dirty := "", false
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				rev = s.Value
			case "vcs.modified":
				dirty = s.Value == "true"
			}
		}
	}
	b := strings.Builder{}
	b.WriteString("fabric/")
	b.WriteString(Version)
	if rev != "" {
		b.WriteString(" ")
		if len(rev) > 9 {
			rev = rev[:9]
		}
		b.WriteString(rev)
		if dirty {
			b.WriteString("+")
		}
	}
	return b.String()
}

// agentOf is the software label a connected peer announced on identify;
// empty when unknown. A node from before this label announces libp2p's
// default agent string, reported as is.
func (d *Daemon) agentOf(p string) string {
	id, err := peer.Decode(p)
	if err != nil {
		return ""
	}
	v, err := d.Host.Peerstore().Get(id, "AgentVersion")
	if err != nil {
		return ""
	}
	s, _ := v.(string)
	return s
}
