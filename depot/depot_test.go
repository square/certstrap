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
	"bytes"
	"os"
	"testing"
)

const (
	data = "It is a trap only!"
	dir  = ".certstrap-test"
)

var (
	tag       = &Tag{"host.pem", 0600}
	tag2      = &Tag{"host2.pem", 0600}
	wrongTag  = &Tag{"host.pem", 0666}
	wrongTag2 = &Tag{"host.pem2", 0600}
)

func getDepot(t *testing.T) *FileDepot {
	os.RemoveAll(dir)

	d, err := NewFileDepot(dir)
	if err != nil {
		t.Fatal("Failed init Depot:", err)
	}
	return d
}

// TestDepotCRUD tests to create, update and delete data
func TestDepotCRUD(t *testing.T) {
	d := getDepot(t)
	defer os.RemoveAll(dir)

	if err := d.Put(tag, []byte(data)); err != nil {
		t.Fatal("Failed putting file into Depot:", err)
	}

	dataRead, err := d.Get(tag)
	if err != nil {
		t.Fatal("Failed getting file from Depot:", err)
	}
	if !bytes.Equal(dataRead, []byte(data)) {
		t.Fatal("Failed getting the previous data")
	}

	if err = d.Put(tag, []byte(data)); err == nil || !os.IsExist(err) {
		t.Fatal("Expect not to put file into Depot:", err)
	}

	if err := d.Delete(tag); err != nil {
		t.Fatal("Failed to delete a tag:", err)
	}

	if d.Check(tag) {
		t.Fatal("Expected the tag to be deleted")
	}
}

func TestDepotPutNil(t *testing.T) {
	d := getDepot(t)
	defer os.RemoveAll(dir)

	if err := d.Put(tag, nil); err == nil {
		t.Fatal("Expect not to put nil into Depot:", err)
	}

	if err := d.Put(tag, []byte(data)); err != nil {
		t.Fatal("Failed putting file into Depot:", err)
	}

	if err := d.Delete(tag); err != nil {
		t.Fatal("Failed to delete a tag:", err)
	}
}

func TestDepotCheckFailure(t *testing.T) {
	d := getDepot(t)
	defer os.RemoveAll(dir)

	if err := d.Put(tag, []byte(data)); err != nil {
		t.Fatal("Failed putting file into Depot:", err)
	}

	if d.Check(wrongTag) {
		t.Fatal("Expect not to checking out file with insufficient permission")
	}

	if d.Check(wrongTag2) {
		t.Fatal("Expect not to checking out file with nonexist name")
	}

	if err := d.Delete(tag); err != nil {
		t.Fatal("Failed to delete a tag:", err)
	}
}

func TestDepotGetFailure(t *testing.T) {
	d := getDepot(t)
	defer os.RemoveAll(dir)

	if err := d.Put(tag, []byte(data)); err != nil {
		t.Fatal("Failed putting file into Depot:", err)
	}

	if _, err := d.Get(wrongTag); err == nil {
		t.Fatal("Expect not to checking out file with insufficient permission")
	}

	if _, err := d.Get(wrongTag2); err == nil {
		t.Fatal("Expect not to checking out file with nonexist name")
	}

	if err := d.Delete(tag); err != nil {
		t.Fatal("Failed to delete a tag:", err)
	}
}

func TestDepotList(t *testing.T) {
	d := getDepot(t)
	defer os.RemoveAll(dir)

	if err := d.Put(tag, []byte(data)); err != nil {
		t.Fatal("Failed putting file into Depot:", err)
	}
	if err := d.Put(tag2, []byte(data)); err != nil {
		t.Fatal("Failed putting file into Depot:", err)
	}

	tags := d.List()
	if len(tags) != 2 {
		t.Fatal("Expect to list 2 instead of", len(tags))
	}
	if tags[0].name != tag.name || tags[1].name != tag2.name {
		t.Fatal("Failed getting file tags back")
	}
}

func TestDepotGetFile(t *testing.T) {
	d := getDepot(t)
	defer os.RemoveAll(dir)

	if err := d.Put(tag, []byte(data)); err != nil {
		t.Fatal("Failed putting file into Depot:", err)
	}

	file, err := d.GetFile(tag)
	if err != nil {
		t.Fatal("Failed getting file from Depot:", err)
	}
	if !bytes.Equal(file.Data, []byte(data)) {
		t.Fatal("Failed getting the previous data")
	}

	if file.Info.Mode() != tag.perm {
		t.Fatal("Failed setting permission")
	}
}
