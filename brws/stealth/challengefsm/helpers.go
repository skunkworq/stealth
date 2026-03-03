package challengefsm

import "net/url"

// deriveBaseURL extracts scheme + host from a URL.
func deriveBaseURL(targetURL string) string {
	u, err := url.Parse(targetURL)
	if err != nil {
		return targetURL
	}
	return u.Scheme + "://" + u.Host
}

// deriveVerifyURL constructs the captcha verify endpoint from the target URL.
func deriveVerifyURL(targetURL string) string {
	u, err := url.Parse(targetURL)
	if err != nil {
		return targetURL + "/api/captcha/verify"
	}
	u.Path = "/api/captcha/verify"
	u.RawQuery = ""
	return u.String()
}
