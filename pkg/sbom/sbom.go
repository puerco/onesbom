// SPDX-FileCopyrightText: Copyright 2023 The OneSBOM Authors
// SPDX-License-Identifier: Apache-2.0

package sbom

import (
	"errors"
	"fmt"
)

type Document struct {
	Metadata      interface{}
	NodeList      NodeList
	rootElements  NodeList
	nodes         map[string]*Node
	Relationships []Relationship
	Files         map[string]File
	Packages      map[string]Package
}

// AddNode adds a node the the document
func (doc *Document) AddNode(n Node) error {
	if n.ID() == "" {
		return errors.New("node has empty ID string")
	}

	// Check if the node is already in the doc
	for _, testID := range doc.NodeList.Identifiers {
		if testID == n.ID() {
			return fmt.Errorf("node %s is already in the document", n.ID())
		}
	}

	if err := n.linkDocument(doc); err != nil {
		return fmt.Errorf("linking node to document")
	}
	doc.NodeList.Identifiers = append(doc.NodeList.Identifiers, n.ID())

	switch cn := n.(type) {
	case *File:
		doc.Files[cn.ID()] = *cn
	case *Package:
		doc.Packages[cn.ID()] = *cn
	}
	doc.nodes[n.ID()] = &n
	return nil
}

// AddRelationshipFromIDs adds a new relationship to the document by getting two
// element IDs and a relationship type. The elements named must exist in the node
// list or the call wil return an error
func (doc *Document) AddRelationshipFromIDs(sourceID, relType, destID string) error {
	if sourceID == "" {
		return fmt.Errorf("source ID cannot be an empty string")
	}
	if destID == "" {
		return fmt.Errorf("destination ID cannot be an empty string")
	}
	var sourceElement, destElement *Node
	for i := range doc.nodes {
		if i == sourceID {
			sourceElement = doc.nodes[i]
		}
		if i == destID {
			destElement = doc.nodes[i]
		}
	}

	if sourceElement == nil {
		return fmt.Errorf("unable to find source element with ID %s", sourceID)
	}

	if sourceElement == nil {
		return fmt.Errorf("unable to find destination element with ID %s", sourceID)
	}

	return doc.AddRelationship(
		sourceElement, relType, &NodeList{
			ProtoNodeList: ProtoNodeList{
				Identifiers: []string{(*destElement).ID()},
			},
		},
	)
}

// CreateRelationship adds a new relationship to the document
func (doc *Document) AddRelationship(sourceElement *Node, relType string, destElement *NodeList) error {
	if sourceElement == nil {
		return errors.New("source element is nil")
	}
	if destElement == nil {
		return errors.New("destination element is nil")
	}

	var foundSource, foundDest bool
	for id, n := range doc.nodes {
		if sourceElement == n {
			foundSource = true
		}

		// look for the target nodes
		foundDestinations := 0
		for _, sb := range destElement.Identifiers {
			if sb == id {
				foundDestinations++
			}
		}
		if foundDestinations == len(destElement.Identifiers) {
			foundDest = true
		}

		if foundDest && foundSource {
			break
		}
	}

	if !foundDest {
		return errors.New("unable to find destination element")
	}

	if !foundSource {
		return errors.New("unable to find source element")
	}

	if destElement.Document == nil {
		destElement.Document = doc
	}

	doc.Relationships = append(doc.Relationships, Relationship{
		SourceID: (*sourceElement).ID(),
		Target:   destElement,
		Type:     RelationshipType(relType),
	})
	return nil
}

// AddRootElementFromID adds an element to the top level by
// specifying its ID
func (doc *Document) AddRootElementFromID(id string) error {
	node := doc.GetElementByID(id)
	if node == nil {
		return fmt.Errorf("element %s not found", id)
	}
	return doc.AddRootElement(node)
}

// AddRootElement adds an element to the top level list of elements
func (doc *Document) AddRootElement(node *Node) error {
	if node == nil {
		return fmt.Errorf("new root node is empty")
	}

	// If the node is not in the docs nodelist, add
	if _, ok := doc.nodes[(*node).ID()]; !ok {
		doc.nodes[(*node).ID()] = node
	}

	for _, id := range doc.rootElements.Identifiers {
		if id == (*node).ID() {
			return nil
		}
	}

	doc.rootElements.Identifiers = append(doc.rootElements.Identifiers, (*node).ID())
	return nil
}

// RootElements returns the list of pointers to the top level elements of the
// document.
func (doc *Document) RootElements() NodeList {
	return doc.rootElements
}

// GetElementByID gets an ID and returns a pointer to the element
func (doc *Document) GetElementByID(id string) *Node {
	for tid := range doc.nodes {
		if tid == id {
			return doc.nodes[tid]
		}
	}
	return nil
}
