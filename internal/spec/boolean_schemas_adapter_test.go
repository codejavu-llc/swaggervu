package spec

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestNormalize31BooleanPreservesUnrelatedData(t *testing.T) {
	// The adapter must not round a user's large example number or interpret
	// schema-looking keys inside ordinary data as actual schema locations.
	body := []byte(`{
  "openapi":"3.1.0",
  "info":{"title":"x","version":"1"},
  "paths":{
    "/x":{"get":{"responses":{"200":{"description":"ok"}}}},
    "x-data":{"get":{"responses":{"200":{"content":{"application/json":{"schema":false}}}}}}
  },
  "components":{
    "schemas":{"Any":true},
    "examples":{"Data":{"value":{"schema":false,"large":9007199254740993}}}
  },
  "x-data":{"properties":{"allowed":true},"items":false,"number":1.234567890123456789}
}`)
	fixed, changed := normalize31BooleanSchemas(body)
	if !changed {
		t.Fatal("boolean component was not adapted")
	}
	want := []byte(strings.Replace(string(body), `"Any":true`, `"Any":{}`, 1))
	decode := func(data []byte) any {
		t.Helper()
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.UseNumber()
		var value any
		if err := decoder.Decode(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	if !reflect.DeepEqual(decode(fixed), decode(want)) {
		t.Fatalf("unrelated values changed:\n%s", fixed)
	}
}
