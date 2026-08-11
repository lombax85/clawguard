// ClawGuard's sidecar needs only the FTP backend, the FTP server, and the
// password-obscuring helper. Keeping the command surface small avoids shipping
// unrelated cloud-storage backends in the trusted gateway container.
package main

import (
	_ "github.com/rclone/rclone/backend/ftp"
	_ "github.com/rclone/rclone/backend/local"
	"github.com/rclone/rclone/cmd"
	_ "github.com/rclone/rclone/cmd/obscure"
	_ "github.com/rclone/rclone/cmd/serve/ftp"
)

func main() {
	cmd.Main()
}
