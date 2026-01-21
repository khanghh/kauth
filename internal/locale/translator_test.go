package locale

import (
	"fmt"
	"testing"
)

func TestTranlator(t *testing.T) {
	translator := Translator{
		translations: TranslationMap{
			"hello": "hello $1, age $0",
		},
	}
	fmt.Println(translator.T("hello", "world", 1))
}
