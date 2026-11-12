package journal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// Reject duplicate object keys before decoding typed state. Last-wins JSON is
// inappropriate for lease and effect authority.
func strictDecode(data []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var value func() error
	value = func() error {
		token, err := dec.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for dec.More() {
				key, err := dec.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return fmt.Errorf("duplicate key")
				}
				seen[name] = true
				if err = value(); err != nil {
					return err
				}
			}
		case '[':
			for dec.More() {
				if err = value(); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("unexpected delimiter")
		}
		_, err = dec.Token()
		return err
	}
	if err := value(); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("trailing value")
	}
	typed := json.NewDecoder(bytes.NewReader(data))
	typed.DisallowUnknownFields()
	return typed.Decode(out)
}
