package stealth_test

import "testing"

func skipExternalNetworkIssue(t *testing.T, target string, err error) {
	t.Helper()
	t.Skipf("skipping external network integration for %s: %v", target, err)
}
