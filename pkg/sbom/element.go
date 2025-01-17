// SPDX-FileCopyrightText: Copyright 2023 The OneSBOM Authors
// SPDX-License-Identifier: Apache-2.0

package sbom

import "github.com/onesbom/onesbom/pkg/license"

// Element is a common ancestor of Package and File that houses
// the common functions among them
type Element struct {
	document         *Document
	id               string
	Name             string
	URL              string
	Comment          string
	LicenseComments  string
	Copyright        string
	LicenseConcluded license.Expression
	Hashes           map[string]string
}

// ID returns the ID of the element
func (e *Element) ID() string {
	return e.id
}

func (e *Element) Relationships() []Relationship {
	rels := []Relationship{}
	for _, r := range e.document.Relationships {
		if (*r.Source).ID() == e.ID() {
			rels = append(rels, r)
		}
	}
	return rels
}
