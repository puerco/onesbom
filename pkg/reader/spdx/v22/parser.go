package v22

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	spdx23 "github.com/onesbom/onesbom/pkg/formats/spdx/v23"
	"github.com/onesbom/onesbom/pkg/license"
	"github.com/onesbom/onesbom/pkg/reader/options"
	"github.com/onesbom/onesbom/pkg/sbom"
)

type Parser struct{}

func (s *Parser) Parse(opts *options.Options, f io.Reader) (*sbom.Document, error) {
	return s.ParseJSON(opts, f)
}

// ParseJSON reads in a json stream and returns a new SBOM
func (s *Parser) ParseJSON(opts *options.Options, f io.Reader) (*sbom.Document, error) {
	spdxDoc := &spdx23.Document{}
	dc := json.NewDecoder(f)
	if err := dc.Decode(spdxDoc); err != nil {
		return nil, fmt.Errorf("decoding document: %w", err)
	}

	// Assign the document to the new sbom
	bom := &sbom.Document{}

	// Assign the document metadata
	for i := range spdxDoc.Packages {
		p := sbom.Package{}
		p.SetID(strings.TrimPrefix(spdxDoc.Packages[i].ID, spdx23.IDPrefix))

		p.Hashes = map[string]string{}
		for _, cs := range spdxDoc.Packages[i].Checksums {
			p.Hashes[cs.Algorithm] = cs.Value
		}

		if spdxDoc.Packages[i].ExternalRefs != nil {
			p.Identifiers = []sbom.Identifier{}
			for _, extid := range spdxDoc.Packages[i].ExternalRefs {
				p.Identifiers = append(p.Identifiers, sbom.Identifier{
					Type:  extid.Type,
					Value: extid.Locator,
				})
			}
		}

		// License data
		p.License = license.Expression(spdxDoc.Packages[i].LicenseDeclared)
		p.LicenseConcluded = license.Expression(spdxDoc.Packages[i].LicenseConcluded)

		if err := bom.AddNode(&p); err != nil {
			return nil, fmt.Errorf("adding package to document: %w", err)
		}
	}

	// Assign the document metadata
	for i := range spdxDoc.Files {
		f := sbom.File{}
		f.SetID(strings.TrimPrefix(spdxDoc.Files[i].ID, spdx23.IDPrefix))

		f.Hashes = map[string]string{}
		for _, cs := range spdxDoc.Files[i].Checksums {
			f.Hashes[cs.Algorithm] = cs.Value
		}

		// License data found in files
		if spdxDoc.Files[i].LicenseInfoInFile != nil {
			for _, le := range spdxDoc.Files[i].LicenseInfoInFile {
				f.Licenses = append(f.Licenses, license.Expression(le))
			}
		}

		if err := bom.AddNode(&f); err != nil {
			return nil, fmt.Errorf("adding file to document: %w", err)
		}
	}

	// Add the root level elements
	if spdxDoc.DocumentDescribes != nil {
		for _, id := range spdxDoc.DocumentDescribes {
			if err := bom.AddRootElementFromID(strings.TrimPrefix(id, spdx23.IDPrefix)); err != nil {
				return nil, fmt.Errorf("adding root element: %s", err)
			}
		}
	}

	// Add the document relationships
	for _, rdata := range spdxDoc.Relationships {
		if err := bom.AddRelationshipFromIDs(
			strings.TrimPrefix(rdata.Element, spdx23.IDPrefix),
			rdata.Type,
			strings.TrimPrefix(rdata.Related, spdx23.IDPrefix),
		); err != nil {
			return nil, fmt.Errorf("adding new relationship to document: %w", err)
		}
	}

	return bom, nil
}
