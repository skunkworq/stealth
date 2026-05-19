package detection

import (
	"fmt"
	"time"
)

// generateRequestID creates a unique request identifier based on the current timestamp.
func generateRequestID() string {
	return fmt.Sprintf("req_%d", time.Now().UnixNano())
}
