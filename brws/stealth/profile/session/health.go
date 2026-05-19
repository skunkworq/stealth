package session

import "github.com/skunkworq/stealth/brws/core/trust"

// Type aliases so callers within this package continue to compile unchanged.
type HealthConfig = trust.HealthConfig
type BanSignal = trust.BanSignal
type HealthScore = trust.HealthScore

var DefaultHealthConfig = trust.DefaultHealthConfig
var NewHealthScore = trust.NewHealthScore
