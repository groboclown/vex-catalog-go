package template_test

import (
	"testing"

	"github.com/groboclown/vex-catalog-go/pkg/catalog/template"
	"github.com/package-url/packageurl-go"
)

func TestPatternParser(t *testing.T) {
	t.Parallel()

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
		{p: "{%VULN", e: "{%VULN"},
		{p: "{abc}", e: "{abc}"},
		{p: "{ABC}", e: "{ABC}"},
		{p: "{%abc}", e: "{%abc}"},
		{p: "{%ABC}", e: "{%ABC}"},
		{p: "{VULN}", e: "CVE-2023-98765"},
		{p: "{%VULN}", e: "CVE-2023-98765"},
		{p: "a-{VULN}-b", e: "a-CVE-2023-98765-b"},
		{p: "{VULN:a}", e: "{VULN:a}"},
		{p: "{VULN:0}", e: "{VULN:0}"},
		{p: "{%VULN:0}", e: "{%VULN:0}"},
		{p: "{ABC:1}", e: "{ABC:1}"},
		{p: "{abc:1}", e: "{abc:1}"},
		{p: "{%ABC:1}", e: "{%ABC:1}"},
		{p: "{%abc:1}", e: "{%abc:1}"},
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
		{p: "{%VULN:-0}", e: "{%VULN:-0}"},
		{p: "{abc:-1}", e: "{abc:-1}"},
		{p: "{%abc:-1}", e: "{%abc:-1}"},
		{p: "{ABC:-1}", e: "{ABC:-1}"},
		{p: "{%ABC:-1}", e: "{%ABC:-1}"},
		{p: "{VULN:-1}", e: "5"},
		{p: "{VULN:-01}", e: "5"},
		{p: "{VULN:-2}", e: "65"},
		{p: "{VULN:-13}", e: "VE-2023-98765"},
		{p: "{VULN:-14}", e: "CVE-2023-98765"},
		{p: "{VULN:-15}", e: "CVE-2023-98765"},
		{p: "{VULN:-99999999999}", e: "CVE-2023-98765"},
		{p: "{VULN:2:5", e: "{VULN:2:5"},
		{p: "{VULN:0:5}", e: "{VULN:0:5}"},
		{p: "{VULN:5:2}", e: "{VULN:5:2}"},
		{p: "{VULN:-5:2}", e: "{VULN:-5:2}"},
		{p: "{VULN:1:2a}", e: "{VULN:1:2a}"},
		{p: "{VULN:1a:2}", e: "{VULN:1a:2}"},
		{p: "{VULN:a:2}", e: "{VULN:a:2}"},
		{p: "{VULN:1:a}", e: "{VULN:1:a}"},
		{p: "{abc:2:5}", e: "{abc:2:5}"},
		{p: "{%abc:2:5}", e: "{%abc:2:5}"},
		{p: "{ABC:2:5}", e: "{ABC:2:5}"},
		{p: "{%ABC:2:5}", e: "{%ABC:2:5}"},
		{p: "{VULN:2:5}", e: "VE-2"},
		{p: "{%VULN:2:5}", e: "VE-2"},
		{p: "{VULN:2:99999}", e: "VE-2023-98765"},
		{p: "{VULN:2:5:6}", e: "{VULN:2:5:6}"},
		{p: "{%VULN:2:5:6}", e: "{%VULN:2:5:6}"},
		{p: "{VULN:99999:999999}", e: ""},
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
		{p: "{VULN@99999999}", e: "CVE-2023-98765"},
		{p: "{VULN@-", e: "{VULN@-"},
		{p: "{VULN@-a", e: "{VULN@-a"},
		{p: "{VULN@-1", e: "{VULN@-1"},
		{p: "{VULN@-0}", e: "{VULN@-0}"},
		{p: "{VULN@-1}", e: "98765"},
		{p: "{VULN@-2}", e: "2023-98765"},
		{p: "{VULN@-3}", e: "CVE-2023-98765"},
		{p: "{VULN@-4}", e: "CVE-2023-98765"},
		{p: "{VULN@-99999999999}", e: "CVE-2023-98765"},
		{p: "{VULN@1:", e: "{VULN@1:"},
		{p: "{VULN@1:}", e: "{VULN@1:}"},
		{p: "{VULN@0:1}", e: "{VULN@0:1}"},
		{p: "{VULN@1:2", e: "{VULN@1:2"},
		{p: "{VULN@2:1}", e: "{VULN@2:1}"},
		{p: "{VULN@a:1}", e: "{VULN@a:1}"},
		{p: "{VULN@1a:2}", e: "{VULN@1a:2}"},
		{p: "{VULN@1:a}", e: "{VULN@1:a}"},
		{p: "{VULN@1:2a}", e: "{VULN@1:2a}"},
		{p: "{VULN@1:1}", e: "CVE"},
		{p: "{VULN@1:2}", e: "CVE-2023"},
		{p: "{VULN@2:3}", e: "2023-98765"},
		{p: "{VULN@2:4}", e: "2023-98765"},
		{p: "{VULN@2:5}", e: "2023-98765"},
		{p: "{VULN@5:17}", e: ""},
		{p: "{ENVIRON}", e: "npm"},
		{p: "{%ENVIRON}", e: "npm"},
		{p: "{MODULE}", e: "@mui"},
		{p: "{%MODULE}", e: "%40mui"},
		{p: "{NAME}", e: "x-license"},
		{p: "{%NAME}", e: "x-license"},
		{p: "{VERSION}", e: "1.9.1-beta-_1"},
		{p: "{%VERSION}", e: "1.9.1-beta-_1"},
		{p: "{VERSION@-1}", e: "1"},
		{p: "{VERSION@-2}", e: "beta-_1"},
		{p: "{VERSION@3:4}", e: "1-beta"},
		{p: "{VERSION@3:5}", e: "1-beta-_1"},
		{p: "{VERSION@5:5}", e: "1"},
		{p: "{VERSION@5:9}", e: "1"},
	}

	for _, v := range data {
		t.Run(v.p, func(t *testing.T) {
			t.Parallel()
			pattern := template.ParsePattern(v.p)
			result := pattern.Evaluate(&purl, "CVE-2023-98765")
			if result != v.e {
				t.Errorf("expected %q, found %q", v.e, result)
			}
		})
	}
}
