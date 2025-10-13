package template_test

import (
	"testing"

	"github.com/groboclown/vex-catalog-go/pkg/catalog/template"
	"github.com/package-url/packageurl-go"
)

func TestPatternParser(t *testing.T) {
	purl, err := packageurl.FromString("pkg:npm/%40mui/x-license@1.9.1-beta-_1")
	if err != nil {
		t.Fatalf("failed to parse purl: %v", err)
	}
	data := []struct {
		p string
		e string
	}{
		{p: "{", e: "{"},
		{p: "{}", e: "{}"},
		{p: "{{VULN}", e: "{VULN}"},
		{p: "{VULN", e: "{VULN"},
		{p: "{VULN}", e: "CVE-2023-98765"},
		{p: "a-{VULN}-b", e: "a-CVE-2023-98765-b"},
		{p: "{VULN:a}", e: "{VULN:a}"},
		{p: "{VULN:0}", e: "{VULN:0}"},
		{p: "{VULN:", e: "{VULN:"},
		{p: "{VULN:}", e: "{VULN:}"},
		{p: "{VULN:1", e: "{VULN:1"},
		{p: "{VULN:1a}", e: "{VULN:1a}"},
		{p: "{VULN:1a", e: "{VULN:1a"},
		{p: "{VULN:1}", e: "C"},
		{p: "{VULN:01}", e: "C"},
		{p: "{VULN:2}", e: "CV"},
		{p: "{VULN:3}", e: "CVE"},
		{p: "{VULN:13}", e: "CVE-2023-9876"},
		{p: "{VULN:14}", e: "CVE-2023-98765"},
		{p: "{VULN:15}", e: "CVE-2023-98765"},
		{p: "{VULN:99999999999}", e: "CVE-2023-98765"},
		{p: "{VULN:-", e: "{VULN:-"},
		{p: "{VULN:-}", e: "{VULN:-}"},
		{p: "{VULN:-1", e: "{VULN:-1"},
		{p: "{VULN:-0}", e: "{VULN:-0}"},
		{p: "{VULN:-a}", e: "{VULN:-a}"},
		{p: "{VULN:-0a}", e: "{VULN:-0a}"},
		{p: "{VULN:-0a", e: "{VULN:-0a"},
		{p: "{VULN:-1}", e: "5"},
		{p: "{VULN:-01}", e: "5"},
		{p: "{VULN:-2}", e: "65"},
		{p: "{VULN:-13}", e: "VE-2023-98765"},
		{p: "{VULN:-14}", e: "CVE-2023-98765"},
		{p: "{VULN:-15}", e: "CVE-2023-98765"},
		{p: "{VULN:-99999999999}", e: "CVE-2023-98765"},
		{p: "{VULN@a}", e: "{VULN@a}"},
		{p: "{VULN@}", e: "{VULN@}"},
		{p: "{VULN@", e: "{VULN@"},
		{p: "{VULN@a", e: "{VULN@a"},
		{p: "{VULN@0", e: "{VULN@0"},
		{p: "{VULN@1", e: "{VULN@1"},
		{p: "{VULN@}", e: "{VULN@}"},
		{p: "{VULN@0}", e: "{VULN@0}"},
		{p: "{VULN@1}", e: "CVE"},
		{p: "{VULN@2}", e: "CVE-2023"},
		{p: "{VULN@3}", e: "CVE-2023-98765"},
		{p: "{VULN@4}", e: "CVE-2023-98765"},
		{p: "{VULN@-", e: "{VULN@-"},
		{p: "{VULN@-a", e: "{VULN@-a"},
		{p: "{VULN@-1", e: "{VULN@-1"},
		{p: "{VULN@-0}", e: "{VULN@-0}"},
		{p: "{VULN@-1}", e: "98765"},
		{p: "{VULN@-2}", e: "2023-98765"},
		{p: "{VULN@-3}", e: "CVE-2023-98765"},
		{p: "{VULN@-4}", e: "CVE-2023-98765"},
		{p: "{MODULE}", e: "%40mui"},
		{p: "{NAME}", e: "x-license"},
		{p: "{VERSION}", e: "1.9.1-beta-_1"},
		{p: "{VERSION@-1}", e: "1"},
		{p: "{VERSION@-2}", e: "beta-_1"},
	}

	for _, v := range data {
		t.Run(v.p, func(t *testing.T) {
			pattern := template.ParsePattern(v.p)
			result := pattern.Evaluate(&purl, "CVE-2023-98765")
			if result != v.e {
				t.Errorf("expected %q, found %q", v.e, result)
			}
		})
	}
}
