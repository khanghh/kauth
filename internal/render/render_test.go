package render

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// resetRenderState clears globals between tests to avoid cross-test interference.
func resetRenderState() {
	globalVars = nil
	templateDir = ""
	embedTemplate = nil
}

// TestRenderHTML_EmbeddedOnly verifies that when no templateDir is configured,
// RenderHTML uses embedded templates successfully.
func TestRenderHTML_EmbeddedOnly(t *testing.T) {
	resetRenderState()
	if err := Initialize(map[string]interface{}{"siteName": "Embedded"}, ""); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	out, err := RenderHTML("mail/otp-code.html", nil)
	if err != nil {
		t.Fatalf("RenderHTML returned error: %v", err)
	}
	fmt.Println(out)
	if out == "" {
		t.Fatalf("expected non-empty HTML output from embedded template")
	}
}

// TestRenderHTML_DirOverridesEmbedded verifies that a valid template in the
// configured directory overrides the embedded one.
func TestRenderHTML_DirOverridesEmbedded(t *testing.T) {
	resetRenderState()
	tmpDir := t.TempDir()
	subDir := filepath.Join(tmpDir, "mail")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatalf("failed to create subdirectory: %v", err)
	}

	// Create an overriding template file
	name := "error-internal.html"
	path := filepath.Join(tmpDir, "mail", name)
	content := "OVERRIDE_ERROR_INTERNAL"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write temp template: %v", err)
	}

	if err := Initialize(map[string]interface{}{}, tmpDir); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	out, err := RenderHTML("mail/error-internal.html", nil)
	if err != nil {
		t.Fatalf("RenderHTML returned error: %v", err)
	}
	fmt.Println(out)
	if out != content {
		t.Fatalf("expected overridden content %q, got %q", content, out)
	}
}

// TestRenderHTML_FallbackOnDiskFailure ensures that when the disk template is
// unreadable or invalid, RenderHTML falls back to embedded templates.
func TestRenderHTML_FallbackOnDiskFailure(t *testing.T) {
	resetRenderState()
	tmpDir := t.TempDir()

	// Write a syntactically invalid template to force parse failure
	name := "error-internal.html"
	path := filepath.Join(tmpDir, name)
	broken := "{{ ." // invalid Go template syntax
	if err := os.WriteFile(path, []byte(broken), 0o644); err != nil {
		t.Fatalf("failed to write broken temp template: %v", err)
	}

	if err := Initialize(map[string]interface{}{}, tmpDir); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	out, err := RenderHTML("error-internal", nil)
	if err != nil {
		t.Fatalf("RenderHTML should have fallen back to embedded template, got error: %v", err)
	}
	if out == "" {
		t.Fatalf("expected non-empty HTML from embedded fallback")
	}
}
