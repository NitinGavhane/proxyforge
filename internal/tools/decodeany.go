package tools

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// decodeAny parses JSON or YAML into any (object/array/scalar).
func decodeAny(doc string) (any, error) {
	trimmed := strings.TrimSpace(doc)
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		var v any
		if err := json.Unmarshal([]byte(doc), &v); err != nil {
			return nil, err
		}
		return v, nil
	}
	var v any
	if err := yaml.Unmarshal([]byte(doc), &v); err != nil {
		return nil, err
	}
	return v, nil
}

func stdBase64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

var _ = fmt.Sprintf
