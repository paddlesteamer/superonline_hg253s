package cwmp

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"time"
)

const (
	initial_tpl    = "templates/initial.tpl"
	periodic_tpl   = "templates/periodic.tpl"
	conreq_tpl     = "templates/connectionRequest.tpl"
	success_tpl    = "templates/setSuccess.tpl"
	macaddress_tpl = "templates/macAddress.tpl"
)

func GenerateInitialRequestBody(nonce string, serial string, extIP string) ([]byte, error) {

	f, err := os.Open(initial_tpl)
	if err != nil {
		return nil, fmt.Errorf("Error while opening %s: %s", initial_tpl, err.Error())
	}
	defer f.Close()

	xml, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("Error while reading file %s: %s", initial_tpl, err.Error())
	}

	xml = bytes.Replace(xml, []byte("%NONCE%"), []byte(nonce), -1)
	xml = bytes.Replace(xml, []byte("%SERIAL%"), []byte(serial), -1)
	xml = bytes.Replace(xml, []byte("%IP%"), []byte(extIP), -1)

	return xml, nil
}

func GeneratePeriodicInformRequestBody(nonce string, serial string, extIP string) ([]byte, error) {
	f, err := os.Open(periodic_tpl)
	if err != nil {
		return nil, fmt.Errorf("Error while opening %s: %s", periodic_tpl, err.Error())
	}
	defer f.Close()

	xml, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("Error while reading file %s: %s", periodic_tpl, err.Error())
	}

	xml = bytes.Replace(xml, []byte("%NONCE%"), []byte(nonce), -1)
	xml = bytes.Replace(xml, []byte("%SERIAL%"), []byte(serial), -1)
	xml = bytes.Replace(xml, []byte("%IP%"), []byte(extIP), -1)

	currentTime := time.Now()

	xml = bytes.Replace(xml, []byte("%DATE%"), []byte(currentTime.Format("2000-10-10T00:00:00")), -1)

	return xml, nil
}

func GenerateRequestedInformRequestBody(nonce string, serial string, extIP string) ([]byte, error) {
	f, err := os.Open(conreq_tpl)
	if err != nil {
		return nil, fmt.Errorf("Error while opening %s: %s", conreq_tpl, err.Error())
	}
	defer f.Close()

	xml, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("Error while reading file %s: %s", conreq_tpl, err.Error())
	}

	xml = bytes.Replace(xml, []byte("%NONCE%"), []byte(nonce), -1)
	xml = bytes.Replace(xml, []byte("%SERIAL%"), []byte(serial), -1)
	xml = bytes.Replace(xml, []byte("%IP%"), []byte(extIP), -1)

	currentTime := time.Now()

	xml = bytes.Replace(xml, []byte("%DATE%"), []byte(currentTime.Format("2000-10-10T00:00:00")), -1)

	return xml, nil
}

func GenerateSetSuccessInformRequestBody(nonce string) ([]byte, error) {
	f, err := os.Open(success_tpl)
	if err != nil {
		return nil, fmt.Errorf("Error while opening %s: %s", success_tpl, err.Error())
	}
	defer f.Close()

	xml, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("Error while reading file %s: %s", success_tpl, err.Error())
	}

	xml = bytes.Replace(xml, []byte("%NONCE%"), []byte(nonce), -1)

	return xml, nil
}

func GenerateRequestedParamsRequestBody(nonce string, macAddr string) ([]byte, error) {
	f, err := os.Open(macaddress_tpl)
	if err != nil {
		return nil, fmt.Errorf("Error while opening %s: %s", macaddress_tpl, err.Error())
	}
	defer f.Close()

	xml, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("Error while reading file %s: %s", macaddress_tpl, err.Error())
	}

	xml = bytes.Replace(xml, []byte("%NONCE%"), []byte(nonce), -1)
	xml = bytes.Replace(xml, []byte("%MAC%"), []byte(macAddr), -1)

	return xml, nil
}
