// Command vault is the standalone build of the bucket CLI. The same
// commands live in the fabric binary (`fabric bucket …`, or a "vault"
// symlink to it) — this target exists for a data-CLI-only install.
package main

import (
	"os"

	"ioa.rocks/fabric/vault/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:]))
}
