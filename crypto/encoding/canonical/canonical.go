package canonical

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
)

func Canonicalize(v any) (string, error) {
	return CanonicalizeExcluding(v, nil)
}

func CanonicalizeExcluding(v any, exclude []string) (string, error) {
	tree, err := roundTripToCanonicalTree(v)
	if err != nil {
		return "", err
	}
	if len(exclude) > 0 {
		tree = pruneExcludedKeys(tree, toSet(exclude))
	}
	var buf bytes.Buffer
	if err := writeCanonicalValue(&buf, tree); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func Marshal(v any) ([]byte, error) {
	return MarshalExcluding(v, nil)
}

func MarshalExcluding(v any, exclude []string) ([]byte, error) {
	canonical, err := CanonicalizeExcluding(v, exclude)
	if err != nil {
		return nil, err
	}
	return []byte(canonical), nil
}

func roundTripToCanonicalTree(v any) (any, error) {
	payload, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var tree any
	if err := decoder.Decode(&tree); err != nil {
		return nil, err
	}
	return tree, nil
}

func pruneExcludedKeys(value any, exclude map[string]struct{}) any {
	switch typed := value.(type) {
	case []any:
		out := make([]any, len(typed))
		for i, entry := range typed {
			out[i] = pruneExcludedKeys(entry, exclude)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, entry := range typed {
			if _, skipped := exclude[key]; skipped {
				continue
			}
			out[key] = pruneExcludedKeys(entry, exclude)
		}
		return out
	default:
		return value
	}
}

func writeCanonicalValue(buf *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if typed {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		if err := writeJSONString(buf, typed); err != nil {
			return err
		}
	case json.Number:
		normalized, err := normalizeJSONNumber(typed)
		if err != nil {
			return err
		}
		buf.WriteString(normalized)
	case float64:
		buf.WriteString(normalizeFloat64(typed))
	case []any:
		buf.WriteByte('[')
		for i, entry := range typed {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonicalValue(buf, entry); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeJSONString(buf, key); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := writeCanonicalValue(buf, typed[key]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("unsupported canonical value type: %T", value)
	}
	return nil
}

func writeJSONString(buf *bytes.Buffer, value string) error {
	var stringBuf bytes.Buffer
	encoder := json.NewEncoder(&stringBuf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return err
	}
	encoded := bytes.TrimSuffix(stringBuf.Bytes(), []byte{'\n'})
	buf.Write(encoded)
	return nil
}

func normalizeJSONNumber(number json.Number) (string, error) {
	raw := strings.TrimSpace(number.String())
	if raw == "" {
		return "", fmt.Errorf("invalid empty json number")
	}
	if !strings.ContainsAny(raw, ".eE") {
		integer := new(big.Int)
		if _, ok := integer.SetString(raw, 10); !ok {
			return "", fmt.Errorf("invalid json integer: %s", raw)
		}
		return integer.String(), nil
	}

	floatValue, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return "", err
	}
	return normalizeFloat64(floatValue), nil
}

func normalizeFloat64(value float64) string {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return "null"
	}
	if value == 0 {
		return "0"
	}
	formatted := strconv.FormatFloat(value, 'g', -1, 64)
	return normalizeExponent(formatted)
}

func normalizeExponent(input string) string {
	idx := strings.IndexAny(input, "eE")
	if idx == -1 {
		return input
	}
	mantissa := input[:idx]
	exponent := input[idx+1:]
	sign := ""
	if strings.HasPrefix(exponent, "+") {
		exponent = exponent[1:]
	} else if strings.HasPrefix(exponent, "-") {
		sign = "-"
		exponent = exponent[1:]
	}
	exponent = strings.TrimLeft(exponent, "0")
	if exponent == "" {
		exponent = "0"
	}
	return mantissa + "e" + sign + exponent
}

func toSet(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		normalized := strings.TrimSpace(value)
		if normalized == "" {
			continue
		}
		out[normalized] = struct{}{}
	}
	return out
}
