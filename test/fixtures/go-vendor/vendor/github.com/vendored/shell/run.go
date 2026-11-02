// TEST FIXTURE: imitates a module that runs shell commands. Never compiled or run.
package shell

import "os/exec"

func Run(cmd string) error { return exec.Command("sh", "-c", cmd).Run() }
