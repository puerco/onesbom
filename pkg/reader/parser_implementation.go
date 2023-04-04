// SPDX-FileCopyrightText: Copyright 2023 The OneSBOM Authors
// SPDX-License-Identifier: Apache-2.0

package reader

import (
	"fmt"
	"io"
	"os"

	"github.com/onesbom/onesbom/pkg/formats"
)

type parserImplementation interface {
	OpenDocumentFile(string) (io.Reader, error)
	DetectFormat(*Options, io.Reader) (formats.Format, error)
	GetFormatParser(*Options, formats.Format) (FormatParser, error)
}

type defaultParserImplementation struct{}

func (dpi *defaultParserImplementation) OpenDocumentFile(path string) (io.Reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening document file %w", err)
	}
	return f, nil
}

func (dpi *defaultParserImplementation) DetectFormat(*Options, io.Reader) (formats.Format, error) {
	return "", nil
}

func (dpi *defaultParserImplementation) GetFormatParser(*Options, formats.Format) (FormatParser, error) {
	return nil, nil
}
