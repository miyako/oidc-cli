package main

import "testing"

func TestDecodeConfig(t *testing.T) {
	for _, input := range []string{
		`null`, `[]`, `{}`, `{"protocol_version":1,"client_id":"test","client_id":"other"}`,
		`{"protocol_version":1,"client_secret":"oops"}`, `{"protocol_version":null}`,
		`{"protocol_version":1} {}`, `{"protocol_version":1,"open_browser":"false"}`,
	} {
		_, err := decodeConfig([]byte(input))
		if input == "{}" {
			continue
		}
		if err == nil {
			t.Errorf("accepted %s", input)
		}
	}
	c, err := decodeConfig([]byte(`{"protocol_version":1,"issuer":"https://example.com","client_id":"desktop","open_browser":false}`))
	if err != nil || c.OpenBrowser == nil || *c.OpenBrowser {
		t.Fatalf("decode: %+v %v", c, err)
	}
}
