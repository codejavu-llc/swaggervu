// Package data holds embedded wordlists, content matchers, secret regexes,
// and the CVE registry that power SwaggerVu.
package data

import "sort"

// priorityPaths are high-signal, well-known spec locations tried first
// (merged from BishopFox/sj priorityURLs + nuclei swagger-api.yaml).
var priorityPaths = []string{
	"/swagger.json", "/openapi.json", "/swagger.yaml", "/openapi.yaml",
	"/v2/api-docs", "/v3/api-docs", "/v1/api-docs", "/api-docs",
	"/swagger/v1/swagger.json", "/swagger/v1/swagger.yaml",
	"/v2/swagger.json", "/v2/openapi.json", "/v3/openapi.json",
	"/api/swagger.json", "/api/openapi.json", "/api-docs/swagger.json",
	"/api-docs/swagger.yaml", "/swagger-ui/index.html", "/swagger-ui.html",
	"/swagger/index.html", "/webjars/swagger-ui/index.html",
	"/swagger", "/docs", "/openapi", "/apidocs", "/api/docs",
	"/swagger-resources", "/api/swagger", "/swagger/ui/index",
}

// uiPaths are Swagger-UI / ReDoc / Swashbuckle HTML entry points.
var uiPaths = []string{
	"/", "/apidocs/", "/swagger/ui/index", "/swagger/index.html", "/swagger-ui.html",
	"/swagger/swagger-ui.html", "/api/swagger-ui.html", "/api_docs", "/api/index.html",
	"/api/doc", "/api/docs/", "/api/swagger/index.html", "/api/swagger/swagger-ui.html",
	"/api/swagger-ui/api-docs", "/api/api-docs", "/api/apidocs", "/api/swagger",
	"/api/swagger/static/index.html", "/api/swagger-resources",
	"/api/swagger-resources/restservices/v2/api-docs", "/api/__swagger__/", "/api/_swagger_/",
	"/docu", "/docs", "/swagger", "/api-doc", "/doc/",
	"/webjars/swagger-ui/index.html", "/3.0.0/swagger-ui.html",
	"/Swagger", "/Swagger/", "/Swagger/index.html",
	"/V2/api-docs/ui", "/admin/swagger-ui/index.html", "/api-doc/", "/api-docs/",
	"/api-docs/ui/", "/api-docs/v1/index.html", "/api-documentation/index.html",
	"/api/", "/api/api-docs/index.html", "/api/config", "/spec/",
	"/redoc", "/redoc.html", "/rapidoc", "/rapidoc.html",
	"/swagger-ui/", "/swagger-ui/index.html", "/swagger/v2/api-docs", "/swagger/v3/api-docs",
	"/__swagger__/", "/_swagger_/", "/developers/documentation",
}

// jsonPaths are direct spec definition files (JSON/YAML).
var jsonPaths = []string{
	"/swagger.json", "/swagger.yaml", "/swagger.yml", "/api/swagger.json",
	"/api/swagger.yaml", "/api/swagger.yml", "/v1/swagger.json",
	"/v1/swagger.yaml", "/v1/swagger.yml", "/openapi.json",
	"/openapi.yaml", "/openapi.yml", "/api/openapi.json",
	"/api/openapi.yaml", "/api/openapi.yml", "/docs/swagger.json",
	"/docs/swagger.yaml", "/docs/openapi.json", "/docs/openapi.yaml",
	"/api-docs/swagger.json", "/api-docs/swagger.yaml",
	"/swagger/v1/swagger.json", "/swagger/v1/swagger.yaml",
	"/rest/swagger.json", "/rest/swagger.yaml", "/rest-api/swagger.json",
	"/swagger/v1/docs.json", "/api/swagger/docs.json",
	"/swagger/docs/v1.json", "/swagger/swagger.json", "/swagger/swagger.yaml",
	"/api-doc.json", "/api/spec/swagger.json", "/api/spec/swagger.yaml",
	"/api/v1/swagger-ui/swagger.json", "/api/v1/swagger-ui/swagger.yaml",
	"/api/swagger_doc.json", "/v2/swagger.json", "/v2/swagger.yaml",
	"/v3/swagger.json", "/v3/swagger.yaml", "/openapi2.json",
	"/openapi2.yaml", "/openapi2.yml", "/api/v3/openapi.json",
	"/api/v3/openapi.yaml", "/api/v3/openapi.yml", "/spec/swagger.json",
	"/spec/swagger.yaml", "/spec/openapi.json", "/spec/openapi.yaml",
	"/api-docs/swagger-ui.json", "/api-docs/swagger-ui.yaml",
	"/api-docs/openapi.json", "/api-docs/openapi.yaml",
	"/swagger-ui.json", "/swagger-ui.yaml",
	"/api/v2/swagger.json", "/api/v3/swagger.json",
	"/api/v2/api-docs", "/api/v3/api-docs", "/api/v1/api-docs",
	"/api.json", "/api.yaml", "/api.yml",
	"/swagger/v1/openapiv2.json", "/swagger/v2/swagger.json",
	"/swagger/v3/swagger.json", "/swagger/v4/swagger.json",
	"/api/4.0/swagger.json", "/swagger-resources/restservices/v2/api-docs",
}

// extraPaths catch versioned/product-specific and brute-friendly directories
// (merged from apidetector common_endpoints_big + sj prefixDirs).
var extraPaths = []string{
	"/swagger-resources/configuration/ui", "/swagger-resources/configuration/security",
	"/api/swagger-resources", "/api/v1/documentation", "/api/v2/documentation",
	"/api/v3/documentation", "/api/docs", "/api/swagger-ui",
	"/documentation/swagger.json", "/documentation/swagger.yaml",
	"/documentation/swagger-ui.html", "/documentation/swagger-ui",
	"/swagger-ui.html/v2/api-docs", "/swagger-ui.html/v3/api-docs",
	"/api/swagger/v2/api-docs", "/api/swagger/v3/api-docs", "/classicapi/doc/",
	"/api/package_search/v4/documentation", "/api/2/explore/",
	"/apidoc", "/application", "/backoffice/v1/ui",
	"/build/reference/web-api/explore", "/core/latest/swagger-ui/index.html",
	"/csp/gateway/slc/api/swagger-ui.html", "/internal/docs",
	"/rest/v1", "/rest/v3/doc", "/swaggerui", "/ui", "/ui/",
	"/v1", "/v1.0", "/v1.1", "/v2", "/v2.0", "/v3",
	"/v1.x/swagger-ui.html", "/swagger/swagger-ui.html",
	"/swagger/latest/swagger.json", "/swagger/static",
	"/api/api-doc/openapi.json", "/api/api-doc/openapi.yaml",
	"/api/doc.json", "/api/docs.json", "/doc/doc.json", "/doc/swagger.json",
	"/docs/swagger.json", "/docs/v1/swagger.json", "/management/info",
	"/openapi/spec.json", "/swagger-ui/openapi.json", "/public/api-merged.json",
	// Framework defaults seen widely in the wild.
	"/q/openapi", "/q/openapi.json", "/q/openapi.yaml", "/q/swagger-ui", // Quarkus
	"/openapi/v2", "/openapi/v3", // Kubernetes API server
	"/v3/api-docs/swagger-config", "/swagger-config.json", // springdoc
	"/scalar", "/scalar/v1", "/reference", // Scalar API reference
	"/api-docs.json", "/api-docs.yaml",
	"/api/v1/openapi.json", "/api/v2/openapi.json",
	"/v1/openapi.json", "/v2/openapi.json", "/v3/api-docs.yaml",
	"/swagger/docs/v1", "/swagger/docs/v2",
	"/openapi/spec.yaml", "/__docs__/", "/__api__/",
}

var (
	allPaths       []string
	allPathsSorted []string
)

func init() {
	seen := map[string]bool{}
	add := func(list []string) {
		for _, p := range list {
			if !seen[p] {
				seen[p] = true
				allPaths = append(allPaths, p)
			}
		}
	}
	// Priority first (ranked), then the rest in discovery order.
	add(priorityPaths)
	add(jsonPaths)
	add(uiPaths)
	add(extraPaths)

	allPathsSorted = append(allPathsSorted, allPaths...)
	sort.Strings(allPathsSorted)
}

// Paths returns the full, deduplicated discovery wordlist with priority paths first.
func Paths() []string { return allPaths }

// PathsSorted returns the wordlist sorted alphabetically (for --list-paths).
func PathsSorted() []string { return allPathsSorted }

// PriorityPaths returns only the high-signal subset.
func PriorityPaths() []string { return priorityPaths }
