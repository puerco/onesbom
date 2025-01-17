package v23

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/onesbom/onesbom/pkg/formats/spdx"
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
		p := sbom.Package{
			Version:        spdxDoc.Packages[i].Version,
			FileName:       spdxDoc.Packages[i].Filename,
			Description:    spdxDoc.Packages[i].Description,
			Comment:        spdxDoc.Packages[i].Comment,
			PrimaryPurpose: spdxDoc.Packages[i].PrimaryPurpose, // [ "OTHER", "INSTALL", "ARCHIVE", "FIRMWARE", "APPLICATION", "FRAMEWORK", "LIBRARY", "CONTAINER", "SOURCE", "DEVICE", "OPERATING_SYSTEM", "FILE" ]
		}
		p.SetID(strings.TrimPrefix(spdxDoc.Packages[i].ID, spdx23.IDPrefix))

		if spdxDoc.Packages[i].DownloadLocation != spdx.NOASSERTION {
			p.DownloadLocation = spdxDoc.Packages[i].DownloadLocation
		}

		if spdxDoc.Packages[i].HomePage != spdx.NOASSERTION {
			p.URL = spdxDoc.Packages[i].HomePage
		}

		if spdxDoc.Packages[i].Summary != spdx.NOASSERTION {
			p.Summary = spdxDoc.Packages[i].Summary
		}

		if spdxDoc.Packages[i].CopyrightText != spdx.NOASSERTION {
			p.Copyright = spdxDoc.Packages[i].CopyrightText
		}

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
		if spdxDoc.Packages[i].LicenseDeclared != spdx.NOASSERTION {
			p.License = license.Expression(spdxDoc.Packages[i].LicenseDeclared)
		}

		if spdxDoc.Packages[i].LicenseConcluded != spdx.NOASSERTION {
			p.LicenseConcluded = license.Expression(spdxDoc.Packages[i].LicenseConcluded)
		}

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
		// If the source is the document, we add it as a root
		if rdata.Element == spdxDoc.ID {
			if err := bom.AddRootElementFromID(strings.TrimPrefix(rdata.Related, spdx23.IDPrefix)); err != nil {
				return nil, fmt.Errorf("adding root element from relationship: %w", err)
			}
			if rdata.Type != string(sbom.DESCRIBES) {
				// warn here if its a differente relationship
			}
			continue
		}

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
