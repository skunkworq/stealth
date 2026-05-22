package netutil

import (
	"fmt"
	"math/rand"
)

// RandomLocalIP returns a random private IP from one of the three RFC-1918 ranges.
func RandomLocalIP() string {
	switch rand.Intn(3) {
	case 0:
		return fmt.Sprintf("10.%d.%d.%d", rand.Intn(256), rand.Intn(256), rand.Intn(256))
	case 1:
		return fmt.Sprintf("172.%d.%d.%d", 16+rand.Intn(16), rand.Intn(256), rand.Intn(256))
	default:
		return fmt.Sprintf("192.168.%d.%d", rand.Intn(256), rand.Intn(256))
	}
}
