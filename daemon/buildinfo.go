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
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				rev = setting.Value
			case "vcs.modified":
				dirty = setting.Value == "true"
			}
		}
	}
	buf := strings.Builder{}
	buf.WriteString("fabric/")
	buf.WriteString(Version)
	if rev != "" {
		buf.WriteString(" ")
		if len(rev) > 9 {
			rev = rev[:9]
		}
		buf.WriteString(rev)
		if dirty {
			buf.WriteString("+")
		}
	}
	return buf.String()
}

// agentOf is the software label a connected peer announced on identify;
// empty when unknown. A node from before this label announces libp2p's
// default agent string, reported as is.
func (d *Daemon) agentOf(peerID string) string {
	id, err := peer.Decode(peerID)
	if err != nil {
		return ""
	}
	val, err := d.Host.Peerstore().Get(id, "AgentVersion")
	if err != nil {
		return ""
	}
	agent, _ := val.(string)
	return agent
}
