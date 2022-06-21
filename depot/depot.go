/*-
 * Copyright 2015 Square Inc.
 * Copyright 2014 CoreOS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package depot

import (
	"errors"
	"fmt"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
)

const (
	// DefaultFileDepotDir is the default directory where .key/.csr/.crt files can be found
	DefaultFileDepotDir = "out"
)

// Tag includes name and permission requirement
// Permission requirement is used in two ways:
// 1. Set the permission for data when Put
// 2. Check the permission required when Get
// It is set to prevent attacks from other users for FileDepot.
// For example, 'evil' creates file ca.key with 0666 file perm,
// 'core' reads it and uses it as ca.key. It may cause the security
// problem of fake certificate and key.
type Tag struct {
	name string
	perm os.FileMode
}

// Depot is in charge of data storage
type Depot interface {
	Put(tag *Tag, data []byte) error
	Check(tag *Tag) bool
	Get(tag *Tag) ([]byte, error)
	Delete(tag *Tag) error
}

// FileDepot is a implementation of Depot using file system
type FileDepot struct {
	// Absolute path of directory that holds all files
	dirPath string
}

// NewFileDepot creates a new Depot at the specified path
func NewFileDepot(dir string) (*FileDepot, error) {
	dirpath, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}

	return &FileDepot{dirpath}, nil
}

func (d *FileDepot) path(name string) string {
	return filepath.Join(d.dirPath, name)
}

// Put inserts the data into the file specified by the tag
func (d *FileDepot) Put(tag *Tag, data []byte) error {
	if data == nil {
		return errors.New("data is nil")
	}

	if err := os.MkdirAll(d.dirPath, 0755); err != nil {
		return err
	}

	name := d.path(tag.name)
	perm := tag.perm

	file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}

	if _, err := file.Write(data); err != nil {
		file.Close()
		os.Remove(name)
		return err
	}

	file.Close()
	return nil
}

// Check returns whether the file at the tag location exists and has permissions at least as restrictive as the given tag.
func (d *FileDepot) Check(tag *Tag) bool {
	name := d.path(tag.name)
	if fi, err := os.Stat(name); err == nil && checkPermissions(tag.perm, fi.Mode()) {
		return true
	}
	return false
}

func (d *FileDepot) check(tag *Tag) error {
	name := d.path(tag.name)
	fi, err := os.Stat(name)
	if err != nil {
		return err
	}
	if !checkPermissions(tag.perm, fi.Mode()) {
		return fmt.Errorf("permissions too lax for %v: required no more than %v, found %v", name, tag.perm, fi.Mode())
	}
	return nil
}

// checkPermissions returns true if the mode bits in file are a subset of required.
func checkPermissions(required, file fs.FileMode) bool {
	// Clear the bits of required from file. The check passes if there are no remaining bits set.
	return file&^required == 0
}

// Get reads the file specified by the tag
func (d *FileDepot) Get(tag *Tag) ([]byte, error) {
	if err := d.check(tag); err != nil {
		return nil, err
	}
	return ioutil.ReadFile(d.path(tag.name))
}

// Delete removes the file specified by the tag
func (d *FileDepot) Delete(tag *Tag) error {
	return os.Remove(d.path(tag.name))
}

// List returns all tags in the specified depot
func (d *FileDepot) List() []*Tag {
	var tags = make([]*Tag, 0)

	//nolint:errcheck
	filepath.Walk(d.dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(d.dirPath, path)
		if err != nil {
			return nil
		}
		if rel != info.Name() {
			return nil
		}
		tags = append(tags, &Tag{info.Name(), info.Mode()})
		return nil
	})

	return tags
}

// File is a wrapper around a FileInfo and the files data bytes
type File struct {
	Info os.FileInfo
	Data []byte
}

// GetFile returns the File at the specified tag in the given depot
func (d *FileDepot) GetFile(tag *Tag) (*File, error) {
	if err := d.check(tag); err != nil {
		return nil, err
	}
	fi, err := os.Stat(d.path(tag.name))
	if err != nil {
		return nil, err
	}
	b, err := ioutil.ReadFile(d.path(tag.name))
	return &File{fi, b}, err
}
