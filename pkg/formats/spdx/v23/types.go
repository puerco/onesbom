// SPDX-FileCopyrightText: Copyright 2023 The OneSBOM Authors
// SPDX-License-Identifier: Apache-2.0

package v23

import "time"

const (
	Version  = "SPDX-2.3"
	IDPrefix = "SPDXRef-"
)

type Document struct {
	ID                   string                `json:"SPDXID"`
	Name                 string                `json:"name"`
	Version              string                `json:"spdxVersion"`
	DataLicense          string                `json:"dataLicense"`
	Namespace            string                `json:"documentNamespace"`
	CreationInfo         CreationInfo          `json:"creationInfo"`
	DocumentDescribes    []string              `json:"documentDescribes"`
	Files                []File                `json:"files,omitempty"`
	Packages             []Package             `json:"packages"`
	Relationships        []Relationship        `json:"relationships"`
	ExternalDocumentRefs []ExternalDocumentRef `json:"externalDocumentRefs,omitempty"`
}

type Package struct {
	FilesAnalyzed        bool                     `json:"filesAnalyzed"`
	ID                   string                   `json:"SPDXID"`
	Name                 string                   `json:"name"`
	Version              string                   `json:"versionInfo"`
	LicenseDeclared      string                   `json:"licenseDeclared,omitempty"`
	LicenseConcluded     string                   `json:"licenseConcluded,omitempty"`
	Description          string                   `json:"description,omitempty"`
	DownloadLocation     string                   `json:"downloadLocation"`
	Originator           string                   `json:"originator,omitempty"`
	Supplier             string                   `json:"supplier,omitempty"`
	SourceInfo           string                   `json:"sourceInfo,omitempty"`
	CopyrightText        string                   `json:"copyrightText"`
	PrimaryPurpose       string                   `json:"primaryPackagePurpose,omitempty"`
	Filename             string                   `json:"packageFileName"`
	HomePage             string                   `json:"homepage,omitempty"`
	Summary              string                   `json:"summary,omitempty"`
	Comment              string                   `json:"comment,omitempty"`
	ReleaseDate          *time.Time               `json:"ReleaseDate,omitempty"`
	BuildDate            *time.Time               `json:"BuildDate,omitempty"`
	ValidUntilDate       *time.Time               `json:"validUntilDate,omitempty"`
	Attribution          *[]string                `json:"attributionTexts,omitempty"`
	HasFiles             []string                 `json:"hasFiles,omitempty"`
	LicenseInfoFromFiles []string                 `json:"licenseInfoFromFiles,omitempty"`
	Checksums            []Checksum               `json:"checksums"`
	ExternalRefs         []ExternalRef            `json:"externalRefs,omitempty"`
	VerificationCode     *PackageVerificationCode `json:"packageVerificationCode,omitempty"`
}

type File struct {
	ID                string     `json:"SPDXID"`
	Name              string     `json:"fileName"`
	CopyrightText     string     `json:"copyrightText"`
	Comment           string     `json:"comment,omitempty"`
	NoticeText        string     `json:"noticeText,omitempty"`
	LicenseConcluded  string     `json:"licenseConcluded,omitempty"`
	LicenseComments   string     `json:"licenseComments,omitempty"`
	Description       string     `json:"description,omitempty"`
	Attribution       *[]string  `json:"attributionTexts,omitempty"`
	FileTypes         []string   `json:"fileTypes,omitempty"`
	LicenseInfoInFile []string   `json:"licenseInfoInFiles,omitempty"` // List of licenses
	Checksums         []Checksum `json:"checksums"`
}

type Relationship struct {
	Element string `json:"spdxElementId"`
	Type    string `json:"relationshipType"`
	Related string `json:"relatedSpdxElement"`
}

type Checksum struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"checksumValue"`
}

type CreationInfo struct {
	Created            string   `json:"created"` // Date
	Creators           []string `json:"creators"`
	LicenseListVersion string   `json:"licenseListVersion,omitempty"`
}

type ExternalRef struct {
	Category string `json:"referenceCategory"`
	Locator  string `json:"referenceLocator"`
	Type     string `json:"referenceType"`
}

type ExternalDocumentRef struct {
	Checksum           Checksum `json:"checksum"`
	ExternalDocumentID string   `json:"externalDocumentId"`
	SPDXDocument       string   `json:"spdxDocument"`
}

type PackageVerificationCode struct {
	Value         string   `json:"packageVerificationCodeValue,omitempty"`
	ExcludedFiles []string `json:"packageVerificationCodeExcludedFiles,omitempty"`
}
