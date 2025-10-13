# vex-catalog-go

Go library for a VEX document catalog format and discovery method.

VEX (Vulnerability Exploitability Exchange) documents store analysis results of how a product was affected by a vulnerability, either as the source of the vulnerability or has a dependency on something that has the issue against it.

With the move towards using VEX documents as a communication device between projects, teams have created various methods for storing their own documents, or housing a collection of other projects' documents.  With this shift, the community needs a method for discovering the location of the documents, and how to map the project name and affected vulnerability ID to the corresponding document.  

This project aims to construct a common format for the description of how to discover the VEX documents, without needing to hard-code each warehouse's particular method.

Inspiration for this came from existing attempts to store the documents:

* [Canonical's Ubuntu Security Notices](https://github.com/canonical/ubuntu-security-notices).  This uses three formats for storing the vulnerability analysis - they create the initial analysis in USN JSON, an internal Ubuntu Security Team format, then convert that to OSV JSON format, and then to a variant of the OpenVEX format (it uses a metadata object rather than as a set of top-level values).
* [VexHub](https://github.com/aquasecurity/vexhub) attempts to collect VEX documents into one place.  It allows projects to register their site so that the hub crawls the site to get the latest version of the VEX document.  It stores the files based on the source package, so that the files remain unaltered from their original form.
* [Vex Repo Spec](https://github.com/aquasecurity/vex-repo-spec) defines a strict layout for how a VEX warehouse should lay out the URL access route for accessing a specific project's VEX documents.

# The Spec

The spec lives partially as a [JSON Schema](vex-catalog.v1_0.schema.json), but with additional qualifications around the "template" concept.

## Template

The template format consists of a Unicode string, with special properties around text contained in `{}` expressions.

* `{{` escapes the `{` character, allowing for insertion of the `{` character into the text.
* Any `{}` expression that does not match one of the known expressions is inserted into the final text without changes.
* After evaluation, all `{}` expressions are first altered with [percent encoding](https://en.wikipedia.org/wiki/Percent-encoding) before placing into the final string.
* Allowed patterns within the `{}` expression:
  * `{VULN}` - the full vulnerability ID.  This MUST match one of the supported vulnerability ID formats within the document.
  * `{ENVIRON}` - the reporting product's [PURL](https://github.com/package-url/purl-spec) "environment" part, sometimes called the "type" or "protocol".  For the PURL expression `pkg:maven/org.apache.commons`, this would be `maven`.
  * `{MODULE}` - the module of the PURL, sometimes called "namespace".  This is percent decoded from the PURL in the raw form, but will be turned back with the percent encoded.  For a purl like `pkg:npm/%40mui/material@7.3.2`, this is `@mui`.
  * `{NAME}` - the name of the PURL, without the module.  This is percent decoded from the PURL in the raw form, but will be turned back with the percent encoded.
  * `{VERSION}` - the version number of the project to look up.  This uses the project's versioning semantics as-is.
* The `{}` expression also allows selection within the sub-string, following these rules:
  * `{n:x}` - The first *x* characters of the text found from `n`.  For vulnerability ID `ABCD`, `{VULN:1}` means `A`, `{VULN:3}` means `ABC`, `{VULN:6}` means `ABCD`.
  * `{n:-x}` - The last *x* characters of the text found from `n`.  For vulnerability ID `ABCD`, `{VULN:-1}` means `D`, `{VULN:-3}` means `BCD`, `{VULN:-6}` means `ABCD`.
  * `{n:x:y}` - Characters *x* to *y* (inclusive) of the text found from `n`.  For vulnerability ID `ABCD`, `{VULN:2:3}` means `BC`, `{VULN:2:2}` means `B`, `{VULN:8:10}` means an empty string.
  * Following the same kind of rules above, `{n@x}`, `{n@-x}`, and `{n@x:y}` refers instead to "segments" of the text found from `n`.  Here, a "segment" is a collection of text separated by one or more characters from within the set `.-_,:/@`.  If the project version number is `v13.6-beta`, then `{VERSION@1}` is `v13`, `{VERSION@1:2}` is `v13.6`, `{VERSION@2:3}` is `6-beta`, and `{VERSION@1:4}` is `v13.6-beta`.


## Implementation

The Go implementation presented here uses a simple interface to permit concurrent loading of VEX documents.  The caller may implement caching and other techniques, as may the back-end.

The implementation does not attempt to construct a unified idea of a VEX statement on top of the interface.  Instead, it contains all the known formats, with their common implementations, in a single structure.


# License

The VEX catalog spec itself is released under the [CC0 1.0](https://creativecommons.org/public-domain/cc0/) license.

The software in this package is released under the [Apache 2.0](LICENSE) license.

