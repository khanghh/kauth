package sessions

import (
	"fmt"
	"testing"
	"time"

	"github.com/go-viper/mapstructure/v2"
)

func TestXxx(t *testing.T) {
	type TestStruct struct {
		Field1 string    `mapstructure:"csrf_field1"`
		Field2 int       `mapstructure:"csrf_field2"`
		Time   time.Time `mapstructure:"csrf_time"`
	}

	data := map[string]any{
		"csrf_field1": "value1",
		"csrf_field2": 42,
		"csrf_time":   time.Now(),
	}
	testStruct := TestStruct{
		Field1: "value1",
		Field2: 42,
		Time:   time.Now(),
	}

	var resultStruct TestStruct
	resultData := make(map[string]any)
	mapstructure.Decode(data, &resultStruct)
	fmt.Println("resultStruct:", resultStruct)

	mapstructure.Decode(testStruct, &resultData)
	fmt.Println(resultData["csrf_field1"])
	fmt.Println(resultData["csrf_field2"])
	fmt.Println(resultData["csrf_time"])
}
