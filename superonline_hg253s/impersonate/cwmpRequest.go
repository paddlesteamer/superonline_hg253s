package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
)

const (
	initial_tpl = "templates/initial.tpl"
)

func GenerateInitialRequestBody(serial string, extIP string) ([]byte, error) {

	f, err := os.Open(initial_tpl)
	if err != nil {
		return nil, fmt.Errorf("Error while opening %s: %s", initial_tpl, err.Error())
	}
	defer f.Close()

	xml, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("Error while reading file %s: %s", initial_tpl, err.Error())
	}

	xml = bytes.Replace(xml, []byte("%SERIAL%"), []byte(serial), -1)
	xml = bytes.Replace(xml, []byte("%IP%"), []byte(extIP), -1)

	return xml, nil
}
