package strutil

import "os/exec"

func helper() { exec.Command("sh", "-c", "echo test-only") }
