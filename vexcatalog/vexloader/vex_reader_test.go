package vexloader_test

import (
	"bytes"
	_ "embed"
	"testing"

	"github.com/groboclown/vex-catalog-go/vexcatalog/vexloader"
)

//go:embed testdata/CVE-2015-0211.json
var CVE20150211 []byte

func Test_LoadOpenVexFromReader(t *testing.T) {
	v, err := vexloader.LoadOpenVexFromReader(
		bytes.NewReader(CVE20150211),
		"0.2.0-canonical",
	)
	if err != nil {
		t.Fatalf("failed to load VEX: %v", err)
	}
	if v == nil {
		t.Fatalf("expected OpenVEX document, found nil")
	}
	if len(v.Statements) != 2 {
		t.Errorf("expected 2 statements, found %d", len(v.Statements))
	}
	if v.Statements[0].Vulnerability.Name != "CVE-2015-0211" {
		t.Errorf("expected CVE-2015-0211, found %q", v.Statements[0].Vulnerability.Name)
	}
	if v.Statements[1].Vulnerability.Name != "CVE-2015-0211" {
		t.Errorf("expected CVE-2015-0211, found %q", v.Statements[1].Vulnerability.Name)
	}
	if v.Statements[0].Status != "affected" {
		t.Errorf("expected affected, found %q", v.Statements[0].Status)
	}
	if v.Statements[1].Status != "not_affected" {
		t.Errorf("expected not_affected, found %q", v.Statements[1].Status)
	}
}

//go:embed testdata/UBUNTU-CVE-2015-0211.json
var UBUNTUCVE20150211 []byte

func Test_LoadOsvFromReader(t *testing.T) {
	v, err := vexloader.LoadOsvFromReader(
		bytes.NewReader(UBUNTUCVE20150211),
		"1.7.0",
	)
	if err != nil {
		t.Fatalf("failed to load VEX: %v", err)
	}
	if v == nil {
		t.Fatalf("expected OSV document, found nil")
	}
	if v.ID != "UBUNTU-CVE-2015-0211" {
		t.Errorf("expected CVE-2015-0211, found %q", v.ID)
	}
	if len(v.Affected) != 2 {
		t.Fatalf("expected 2 affected entries, found %d", len(v.Affected))
	}
	if v.Affected[0].Package.Purl != "pkg:deb/ubuntu/moodle@3.0.3+dfsg-0ubuntu1?arch=source&distro=xenial" {
		t.Errorf("expected pkg:deb/ubuntu/moodle@3.0.3+dfsg-0ubuntu1?arch=source&distro=xenial, found %q", v.Affected[0].Package.Purl)
	}
	if v.Affected[1].Package.Purl != "pkg:deb/ubuntu/moodle@3.0.3+dfsg-0ubuntu1?arch=source&distro=bionic" {
		t.Errorf("expected pkg:deb/ubuntu/moodle@3.0.3+dfsg-0ubuntu1?arch=source&distro=bionic, found %q", v.Affected[1].Package.Purl)
	}
}

//go:embed testdata/rhsa-2020_1358.json
var RHSA_2020_1358 []byte

func Test_LoadCsafFromReader(t *testing.T) {
	v, err := vexloader.LoadCsafFromReader(
		bytes.NewReader(RHSA_2020_1358),
		"1.0",
	)
	if err != nil {
		t.Fatalf("failed to load VEX: %v", err)
	}
	if v == nil {
		t.Fatalf("expected CSAF document, found nil")
	}
}

//go:embed testdata/openvex-v0.0.1-noversion.json
var OpenVEX_001_NoVersion []byte

func Test_LoadOpenVexFromReader_001_NoVersion(t *testing.T) {
	v, err := vexloader.LoadOpenVexFromReader(
		bytes.NewReader(OpenVEX_001_NoVersion),
		"0.0.1",
	)
	if err != nil {
		t.Fatalf("failed to load VEX: %v", err)
	}
	if v == nil {
		t.Fatalf("expected OpenVEX document, found nil")
	}
}

//go:embed testdata/openvex-v0.0.1.json
var OpenVEX_001 []byte

func Test_LoadOpenVexFromReader_001(t *testing.T) {
	v, err := vexloader.LoadOpenVexFromReader(
		bytes.NewReader(OpenVEX_001),
		"0.0.1",
	)
	if err != nil {
		t.Fatalf("failed to load VEX: %v", err)
	}
	if v == nil {
		t.Fatalf("expected OpenVEX document, found nil")
	}
}

//go:embed testdata/openvex-v0.2.0.json
var OpenVEX_020 []byte

func Test_LoadOpenVexFromReader_020(t *testing.T) {
	v, err := vexloader.LoadOpenVexFromReader(
		bytes.NewReader(OpenVEX_020),
		"0.2.0",
	)
	if err != nil {
		t.Fatalf("failed to load VEX: %v", err)
	}
	if v == nil {
		t.Fatalf("expected OpenVEX document, found nil")
	}
}
