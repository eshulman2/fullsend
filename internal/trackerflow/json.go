package trackerflow

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// DecodeStrict rejects duplicate keys at every nesting level, unknown fields,
// trailing values and deeply nested input. Diagnostics never retain input text.
func DecodeStrict(raw []byte, out any) error {
	if len(raw) == 0 || len(raw) > 1<<20 {
		return errors.New("invalid structured input")
	}
	scanner := json.NewDecoder(bytes.NewReader(raw))
	scanner.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 64 {
			return errors.New("invalid structured input")
		}
		token, err := scanner.Token()
		if err != nil {
			return err
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for scanner.More() {
					key, e := scanner.Token()
					if e != nil {
						return e
					}
					name, ok := key.(string)
					if !ok || seen[name] {
						return errors.New("invalid structured input")
					}
					seen[name] = true
					if e = value(depth + 1); e != nil {
						return e
					}
				}
				end, e := scanner.Token()
				if e != nil || end != json.Delim('}') {
					return errors.New("invalid structured input")
				}
			case '[':
				for scanner.More() {
					if e := value(depth + 1); e != nil {
						return e
					}
				}
				end, e := scanner.Token()
				if e != nil || end != json.Delim(']') {
					return errors.New("invalid structured input")
				}
			default:
				return errors.New("invalid structured input")
			}
		}
		return nil
	}
	if value(0) != nil {
		return errors.New("invalid structured input")
	}
	if _, err := scanner.Token(); !errors.Is(err, io.EOF) {
		return errors.New("invalid structured input")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return errors.New("invalid structured input")
	}
	return nil
}
