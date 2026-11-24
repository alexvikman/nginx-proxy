package proxy

import (
	"bytes"
	_ "embed"
	"fmt"
	"regexp"
	"strings"
	"text/template"
)

//go:embed nginx.conf.tmpl
var nginxTemplate string

var tmpl = template.Must(template.New("nginx").Funcs(template.FuncMap{
	"dict": func(kv ...any) (map[string]any, error) {
		if len(kv)%2 != 0 {
			return nil, fmt.Errorf("dict: odd number of arguments")
		}
		m := make(map[string]any, len(kv)/2)
		for i := 0; i < len(kv); i += 2 {
			m[kv[i].(string)] = kv[i+1]
		}
		return m, nil
	},
	// nginx's include directive treats * as a glob; wildcard host names
	// such as *.example.com must be escaped to match the literal file.
	"globEscape": func(s string) string { return strings.ReplaceAll(s, "*", `\*`) },
}).Parse(nginxTemplate))

var blankLines = regexp.MustCompile(`\n{3,}`)

// Render produces the nginx configuration for cfg.
func Render(cfg *Config) ([]byte, error) {
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, cfg); err != nil {
		return nil, err
	}
	return append(bytes.TrimSpace(blankLines.ReplaceAll(buf.Bytes(), []byte("\n\n"))), '\n'), nil
}
