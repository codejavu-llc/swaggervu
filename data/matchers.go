package data

import (
	"regexp"
	"strings"
)

// uiMarkers are body substrings that indicate a Swagger/OpenAPI UI or spec
// (sourced from nuclei swagger-api.yaml matchers + sj fingerprints).
var uiMarkers = []string{
	"swagger:",
	"\"swagger\":",
	"'swagger'",
	"Swagger 2.0",
	"Swagger UI",
	"swagger-ui",
	"loadSwaggerUI",
	"id=\"swagger-ui",
	"SwaggerUIBundle",
	"\"openapi\":",
	"openapi:",
	"redoc",
	"ReDoc",
	"rapidoc",
	"api-docs",
	"stoplight-elements",
	"elements-api",
	"Scalar.createApiReference",
	"data-scalar",
}

// VersionRegex extracts a semantic version string from a matched page.
var VersionRegex = regexp.MustCompile(`v?[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}`)

// LooksLikeSwagger reports whether a response body contains a Swagger/OpenAPI marker.
func LooksLikeSwagger(body string) bool {
	lower := strings.ToLower(body)
	for _, m := range uiMarkers {
		if strings.Contains(body, m) || strings.Contains(lower, strings.ToLower(m)) {
			return true
		}
	}
	return false
}

// MatchedMarker returns the first marker found, or "".
func MatchedMarker(body string) string {
	lower := strings.ToLower(body)
	for _, m := range uiMarkers {
		if strings.Contains(body, m) || strings.Contains(lower, strings.ToLower(m)) {
			return m
		}
	}
	return ""
}
