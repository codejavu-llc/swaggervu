package data

import "regexp"

// SecretPattern is a named, compiled secret-detection regex.
type SecretPattern struct {
	Name string
	Re   *regexp.Regexp
}

// rawSecretPatterns merges the TruffleHog-style corpus from intruder-io/autoswagger
// with UndeadSec/SwaggerSpy's set. The SwaggerSpy bugs (missing comma after the JIRA
// pattern, truncated secret_key / api regexes) are fixed here.
var rawSecretPatterns = map[string]string{
	"Slack Token":                   `xox[pborsa]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9-]{20,40}`,
	"Slack Webhook":                 `https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,12}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9_]{24}`,
	"RSA Private Key":               `-----BEGIN RSA PRIVATE KEY-----`,
	"SSH (DSA) Private Key":         `-----BEGIN DSA PRIVATE KEY-----`,
	"SSH (EC) Private Key":          `-----BEGIN EC PRIVATE KEY-----`,
	"OpenSSH Private Key":           `-----BEGIN OPENSSH PRIVATE KEY-----`,
	"PGP Private Key Block":         `-----BEGIN PGP PRIVATE KEY BLOCK-----`,
	"AWS Access Key ID":             `A[SK]IA[0-9A-Z]{16}`,
	"Amazon MWS Auth Token":         `amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`,
	"AWS AppSync GraphQL Key":       `da2-[a-z0-9]{26}`,
	"AWS S3 URL":                    `[a-z0-9.-]+\.s3\.amazonaws\.com`,
	"Facebook Access Token":         `EAACEdEose0cBA[0-9A-Za-z]+`,
	"GitHub Token (classic)":        `ghp_[0-9a-zA-Z]{36}`,
	"GitHub Fine-grained Token":     `github_pat_[0-9a-zA-Z_]{22,255}`,
	"GitHub OAuth Token":            `gho_[0-9a-zA-Z]{36}`,
	"Google API Key":                `AIza[0-9A-Za-z\-_]{35}`,
	"Google OAuth Access Token":     `ya29\.[0-9A-Za-z\-_]+`,
	"Google Cloud OAuth":            `[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`,
	"MailChimp API Key":             `[0-9a-f]{32}-us[0-9]{1,2}`,
	"Mailgun API Key":               `key-[0-9a-zA-Z]{32}`,
	"Password in URL":               `[a-zA-Z]{3,10}://[^/\s:@]{3,40}:[^/\s:@]{3,40}@.{1,100}`,
	"PayPal Braintree Access Token": `access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`,
	"Stripe Live Secret Key":        `sk_live_[0-9a-zA-Z]{24}`,
	"Stripe Restricted Key":         `rk_live_[0-9a-zA-Z]{24}`,
	"Square Access Token":           `sq0atp-[0-9A-Za-z\-_]{22}`,
	"Square OAuth Secret":           `sq0csp-[0-9A-Za-z\-_]{43}`,
	"Twilio API Key":                `SK[0-9a-fA-F]{32}`,
	"Twilio Account SID":            `AC[a-zA-Z0-9]{32}`,
	"Telegram Bot Token":            `[0-9]{8,10}:AA[0-9A-Za-z\-_]{33}`,
	"NPM Access Token":              `npm_[0-9a-zA-Z]{36}`,
	"Heroku API Key":                `[hH]eroku.{0,20}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`,
	"JWT":                           `eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`,
	"JIRA PAT":                      `ATATT[A-Za-z0-9_\-=]{20,}`,
	"Authorization Basic":           `(?i)authorization:\s*basic\s+[a-z0-9=:_\+/-]{8,}`,
	"Authorization Bearer":          `(?i)authorization:\s*bearer\s+[a-z0-9._\-]{10,}`,
	"Generic API Key":               `(?i)api[_-]?key['"\s:=]{1,4}['"]?[0-9a-zA-Z\-_]{16,45}`,
	"Generic Secret":                `(?i)secret[_-]?key['"\s:=]{1,4}['"]?[0-9a-zA-Z\-_]{16,45}`,
	"MySQL Connection URI":          `mysql://[a-zA-Z0-9._%+-]+:[^@\s]+@[a-zA-Z0-9.-]+`,
	"MongoDB Connection URI":        `mongodb(\+srv)?://[a-zA-Z0-9._%+-]+:[^@\s]+@[a-zA-Z0-9.-]+`,
	"Git Credential":                `https?://[^/\s:@]+:[^/\s:@]+@github\.com`,
	"Private IP":                    `\b(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.[0-9]{1,3}\.[0-9]{1,3}\b`,
	// Modern, high-signal prefixed tokens (low false-positive rates).
	"GitLab Personal Access Token": `glpat-[0-9a-zA-Z_\-]{20}`,
	"GitHub App Token":             `(?:ghu|ghs|ghr)_[0-9a-zA-Z]{36}`,
	"OpenAI API Key":               `sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{32,}`,
	"Anthropic API Key":            `sk-ant-[A-Za-z0-9_\-]{20,}`,
	"SendGrid API Key":             `SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}`,
	"Shopify Access Token":         `shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}`,
	"DigitalOcean Token":           `dop_v1_[a-f0-9]{64}`,
	"Postman API Key":              `PMAK-[a-f0-9]{24}-[a-f0-9]{34}`,
	"HashiCorp Vault Token":        `hv[sb]\.[A-Za-z0-9_\-]{24,}`,
	"Databricks Token":             `dapi[a-f0-9]{32}`,
	"Linear API Key":               `lin_api_[0-9A-Za-z]{40}`,
	"Doppler Token":                `dp\.(?:pt|st|sa|scim|audit)\.[A-Za-z0-9]{40,}`,
}

var compiledSecretPatterns []SecretPattern

func init() {
	for name, pat := range rawSecretPatterns {
		re, err := regexp.Compile(pat)
		if err != nil {
			continue // skip any pattern that fails to compile rather than crash
		}
		compiledSecretPatterns = append(compiledSecretPatterns, SecretPattern{Name: name, Re: re})
	}
}

// SecretPatterns returns the compiled secret-detection corpus.
func SecretPatterns() []SecretPattern { return compiledSecretPatterns }
