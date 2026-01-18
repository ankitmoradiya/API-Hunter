// apihunter/internal/export/postman.go
package export

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/apihunter/apihunter/internal/analyzer"
	"github.com/apihunter/apihunter/internal/models"
)

// PostmanExporter generates Postman collection
type PostmanExporter struct{}

// NewPostmanExporter creates a new Postman exporter
func NewPostmanExporter() *PostmanExporter {
	return &PostmanExporter{}
}

type postmanCollection struct {
	Info     postmanInfo     `json:"info"`
	Item     []postmanFolder `json:"item"`
	Variable []postmanVar    `json:"variable"`
}

type postmanInfo struct {
	Name   string `json:"name"`
	Schema string `json:"schema"`
}

type postmanFolder struct {
	Name string        `json:"name"`
	Item []postmanItem `json:"item"`
}

type postmanItem struct {
	Name    string         `json:"name"`
	Request postmanRequest `json:"request"`
}

type postmanRequest struct {
	Method string          `json:"method"`
	URL    postmanURL      `json:"url"`
	Header []postmanHeader `json:"header"`
}

type postmanURL struct {
	Raw   string         `json:"raw"`
	Host  []string       `json:"host"`
	Path  []string       `json:"path"`
	Query []postmanQuery `json:"query,omitempty"`
}

type postmanHeader struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type postmanQuery struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type postmanVar struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Export generates Postman collection JSON file
func (e *PostmanExporter) Export(result *models.ScanResult, groups []analyzer.EndpointGroup, outputDir string) error {
	collection := postmanCollection{
		Info: postmanInfo{
			Name:   result.Target + " API",
			Schema: "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
		},
		Variable: []postmanVar{
			{Key: "baseUrl", Value: result.Target},
			{Key: "auth", Value: ""},
		},
	}

	for _, group := range groups {
		folder := postmanFolder{Name: group.Name}

		for _, ep := range group.Endpoints {
			for _, method := range ep.Methods {
				path := ep.NormalizedPath
				if path == "" {
					path = ep.Path
				}

				pathParts := strings.Split(strings.Trim(path, "/"), "/")

				item := postmanItem{
					Name: method + " " + path,
					Request: postmanRequest{
						Method: method,
						URL: postmanURL{
							Raw:  "{{baseUrl}}" + path,
							Host: []string{"{{baseUrl}}"},
							Path: pathParts,
						},
						Header: []postmanHeader{
							{Key: "Authorization", Value: "{{auth}}"},
						},
					},
				}

				// Add query params
				for _, qp := range ep.QueryParams {
					item.Request.URL.Query = append(item.Request.URL.Query, postmanQuery{
						Key:   qp.Name,
						Value: qp.Example,
					})
				}

				folder.Item = append(folder.Item, item)
			}
		}

		if len(folder.Item) > 0 {
			collection.Item = append(collection.Item, folder)
		}
	}

	// Write to file
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(collection, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(outputDir, "postman_collection.json"), data, 0644)
}
