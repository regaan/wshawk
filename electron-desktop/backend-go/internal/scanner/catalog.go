package scanner

type Payload struct {
	Category string `json:"category"`
	Name     string `json:"name"`
	Value    string `json:"value"`
	Marker   string `json:"marker,omitempty"`
}

var catalog = []Payload{
	{Category: "sqli", Name: "quote-error", Value: "'\"`", Marker: "sql"},
	{Category: "sqli", Name: "boolean-true", Value: "' OR '1'='1'--", Marker: "sql"},
	{Category: "xss", Name: "html-context", Value: `<wshawk-xss data-marker="wshawk_xss_probe">`, Marker: "wshawk_xss_probe"},
	{Category: "xss", Name: "attribute-context", Value: `\"><wshawk-xss data-marker=wshawk_xss_probe>`, Marker: "wshawk_xss_probe"},
	{Category: "command_injection", Name: "shell-separator", Value: ";printf WSHK_CMD_PROBE", Marker: "WSHK_CMD_PROBE"},
	{Category: "command_injection", Name: "windows-separator", Value: "& echo WSHK_CMD_PROBE", Marker: "WSHK_CMD_PROBE"},
	{Category: "nosql_injection", Name: "operator-ne", Value: `{"$ne":null}`, Marker: "$ne"},
	{Category: "path_traversal", Name: "unix-passwd", Value: "../../../../etc/passwd", Marker: "root:"},
	{Category: "path_traversal", Name: "windows-winini", Value: `..\..\..\..\windows\win.ini`, Marker: "[fonts]"},
	{Category: "xxe", Name: "safe-local-entity", Value: `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///nonexistent-wshawk-probe">]><r>&xxe;</r>`, Marker: "nonexistent-wshawk-probe"},
	{Category: "ssrf", Name: "operator-callback", Value: "{{OAST_URL}}", Marker: "oast"},
	{Category: "prototype_pollution", Name: "json-proto", Value: `{"__proto__":{"wshawk_probe":true}}`, Marker: "wshawk_probe"},
	{Category: "redirect", Name: "external-location", Value: "https://wshawk.invalid/redirect-probe", Marker: "wshawk.invalid"},
}

func Catalog() []Payload { return append([]Payload(nil), catalog...) }
