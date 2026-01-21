package locale

import (
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"

	"gopkg.in/yaml.v3"
)

//go:embed lang/vi.yaml
//go:embed lang/en.yaml
var localeFS embed.FS

var (
	defaultTranslator *Translator
	defaultLangDir    = "lang"
)

type TranslationMap map[string]string

type Translator struct {
	translations TranslationMap
}

func (t *Translator) T(key string, params ...any) string {
	text, exists := t.translations[key]
	if !exists {
		return key
	}

	paramMap := make(map[string]string, len(params))
	for i, param := range params {
		if str, ok := param.(fmt.Stringer); ok {
			paramMap[strconv.Itoa(i)] = str.String()
		} else {
			paramMap[strconv.Itoa(i)] = fmt.Sprint(param)
		}
	}

	return os.Expand(text, func(k string) string {
		if v, ok := paramMap[k]; ok {
			return v
		}
		return "$" + k
	})
}

func extractTranslationMaps(langDir string) error {
	if err := os.MkdirAll(langDir, 0755); err != nil {
		return err
	}

	files, err := fs.ReadDir(localeFS, langDir)
	if err != nil {
		return err
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		srcPath := filepath.Join(langDir, file.Name())
		outPath := filepath.Join(langDir, file.Name())

		if _, err := os.Stat(outPath); err == nil {
			continue
		}

		data, err := localeFS.ReadFile(srcPath)
		if err != nil {
			return err
		}

		if err := os.WriteFile(outPath, data, 0644); err != nil {
			return err
		}
	}

	return nil
}

func loadTranslationMap(lang string) (TranslationMap, error) {
	filename := filepath.Join(defaultLangDir, fmt.Sprintf("%s.yaml", filepath.Base(lang)))
	blob, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	translationMap := make(TranslationMap)
	if err := yaml.Unmarshal(blob, &translationMap); err != nil {
		return nil, err
	}
	return translationMap, nil
}

func GetTranslator(lang string) *Translator {
	translations, err := loadTranslationMap(lang)
	if err != nil {
		slog.Error(fmt.Sprintf("Could not load language '%s'", lang), "error", err)
		return defaultTranslator
	}
	return &Translator{translations}
}

func InitLocale(lang string) error {
	if err := extractTranslationMaps(defaultLangDir); err != nil {
		return fmt.Errorf("could not extract language files. %w", err)
	}
	defaultTranslator = GetTranslator(lang)
	if defaultTranslator == nil {
		return fmt.Errorf("failed to initialize locale for language %s", lang)
	}
	return nil
}

func T(key string, params ...any) string {
	if defaultTranslator != nil {
		return defaultTranslator.T(key, params...)
	}
	return key
}
