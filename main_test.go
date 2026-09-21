package main

import "testing"

func TestNormalizeHash(t *testing.T) {
	cases := map[string]string{
		"":                                 "",
		"e19ccf75ee54e06b06a5907af13cef42": "e19ccf75ee54e06b06a5907af13cef42",
		"aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42": "e19ccf75ee54e06b06a5907af13cef42",
		":e19ccf75ee54e06b06a5907af13cef42":                                 "e19ccf75ee54e06b06a5907af13cef42",
	}
	for in, want := range cases {
		if got := normalizeHash(in); got != want {
			t.Errorf("normalizeHash(%q) = %q, want %q", in, got, want)
		}
	}
}
