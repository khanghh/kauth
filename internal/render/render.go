package render

import (
	"embed"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/valyala/bytebufferpool"
)

//go:embed templates/*.html templates/mail/*.html
var embedFS embed.FS
var embedTemplate *template.Template
var templateDir string
var globalVars map[string]interface{}

func Initialize(gVars map[string]interface{}, tmplDir string) error {
	globalVars = gVars
	if tmplDir != "" {
		info, err := os.Stat(tmplDir)
		if err != nil {
			return fmt.Errorf("template directory does not exist: %w", err)
		}
		if !info.IsDir() {
			return fmt.Errorf("template path is not a directory: %s", tmplDir)
		}
		templateDir = tmplDir
	}

	if err := initEmbeddedTemplates(); err != nil {
		return err
	}
	return nil
}

// initEmbeddedTemplates prepares embedded templates for fallback, using names
// that include their relative path (e.g. "mail/otp.html").
func initEmbeddedTemplates() error {
	t := template.New("")
	err := fs.WalkDir(embedFS, "templates", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".html") {
			return nil
		}
		// path is like "templates/foo.html" or "templates/mail/otp.html"
		rel := strings.TrimPrefix(path, "templates/")
		content, readErr := embedFS.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if _, parseErr := t.New(rel).Parse(string(content)); parseErr != nil {
			return parseErr
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to parse embedded templates: %w", err)
	}
	embedTemplate = t
	return nil
}

func RenderHTML(templateName string, vars map[string]interface{}) (string, error) {
	buf := bytebufferpool.Get()
	defer bytebufferpool.Put(buf)

	mergedVars := make(map[string]interface{})
	for k, v := range globalVars {
		mergedVars[k] = v
	}
	for k, v := range vars {
		mergedVars[k] = v
	}

	if !strings.HasSuffix(templateName, ".html") {
		templateName += ".html"
	}

	// On-demand loading when a template directory is set
	if templateDir != "" {
		// Compute absolute file filePath
		filePath := filepath.Join(templateDir, templateName)
		fallback := true
		// Read and compile the specific template with its full logical name
		if contents, err := os.ReadFile(filePath); err == nil {
			if t, err := template.New(templateName).Parse(string(contents)); err == nil {
				if err := t.ExecuteTemplate(buf, templateName, mergedVars); err == nil {
					fallback = false
					return buf.String(), nil
				}
			}
		}
		if fallback {
			log.Printf("Render template %s failed, falling back to embedded", filePath)
		}
	}

	// fallback to embedded templates
	if err := embedTemplate.ExecuteTemplate(buf, templateName, mergedVars); err != nil {
		return "", err
	}
	return buf.String(), nil
}
