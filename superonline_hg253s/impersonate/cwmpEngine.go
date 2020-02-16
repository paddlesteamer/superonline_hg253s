package main

import (
	"fmt"
	"impersonate/cwmp"
	"impersonate/session"
	"strconv"
)

type informType int

const (
	initialInform    = iota
	periodicInform   = iota
	requestedInform  = iota
	setSuccessInform = iota
	requestedParams  = iota
	emptyInform      = iota
)

var (
	serialNo   string
	macAddress string
	externalIP string

	sess *session.Session

	nonceIdx = 37
)

func sendInitialRequest(nonce string) (int, []byte, error) {
	reqBody, err := cwmp.GenerateInitialRequestBody(nonce, serialNo, externalIP)
	if err != nil {
		return 0, nil, fmt.Errorf("Error while generating intial request body: %s\n", reqBody)
	}

	statusCode, respBody, err := sess.SendRequest(reqBody)
	if err != nil {
		return 0, nil, fmt.Errorf("Error during initial request: %s\n", err.Error())
	}

	return statusCode, respBody, nil
}

func sendPeriodicInformRequest(nonce string) (int, []byte, error) {
	reqBody, err := cwmp.GeneratePeriodicInformRequestBody(nonce, serialNo, externalIP)
	if err != nil {
		return 0, nil, fmt.Errorf("Error while generating periodic request body: %s\n", reqBody)
	}

	statusCode, respBody, err := sess.SendRequest(reqBody)
	if err != nil {
		return 0, nil, fmt.Errorf("Error during periodic request: %s\n", err.Error())
	}

	return statusCode, respBody, nil
}

func sendRequestedInformRequest(nonce string) (int, []byte, error) {
	reqBody, err := cwmp.GenerateRequestedInformRequestBody(nonce, serialNo, externalIP)
	if err != nil {
		return 0, nil, fmt.Errorf("Error while generating requestedInform request body: %s\n", reqBody)
	}

	statusCode, respBody, err := sess.SendRequest(reqBody)
	if err != nil {
		return 0, nil, fmt.Errorf("Error during requestedInform request: %s\n", err.Error())
	}

	return statusCode, respBody, nil
}

func sendSetSuccessInformRequest(nonce string) (int, []byte, error) {
	reqBody, err := cwmp.GenerateSetSuccessInformRequestBody(nonce)
	if err != nil {
		return 0, nil, fmt.Errorf("Error while generating set success request body: %s\n", reqBody)
	}

	statusCode, respBody, err := sess.SendRequest(reqBody)
	if err != nil {
		return 0, nil, fmt.Errorf("Error during set success request: %s\n", err.Error())
	}

	return statusCode, respBody, nil
}

func sendRequestedParamsRequest(nonce string, macAddr string) (int, []byte, error) {
	reqBody, err := cwmp.GenerateRequestedParamsRequestBody(nonce, macAddr)
	if err != nil {
		return 0, nil, fmt.Errorf("Error while generating set params request body: %s\n", reqBody)
	}

	statusCode, respBody, err := sess.SendRequest(reqBody)
	if err != nil {
		return 0, nil, fmt.Errorf("Error during set params request: %s\n", err.Error())
	}

	return statusCode, respBody, nil
}

func sendEmptyInformRequest(nonce string) (int, []byte, error) {
	reqBody := make([]byte, 0)

	statusCode, respBody, err := sess.SendRequest(reqBody)
	if err != nil {
		return 0, nil, fmt.Errorf("Error during empty request: %s\n", err.Error())
	}

	return statusCode, respBody, nil

}

func startChain(typ informType) {

	state := typ
	nonce := strconv.Itoa(nonceIdx)

	for {
		var (
			statusCode int
			response   []byte
			err        error
		)
		if state == initialInform {
			statusCode, response, err = sendInitialRequest(nonce)
			nonceIdx++
		} else if state == periodicInform {
			statusCode, response, err = sendPeriodicInformRequest(nonce)
			nonceIdx++
		} else if state == requestedInform {
			statusCode, response, err = sendRequestedInformRequest(nonce)
			nonceIdx++
		} else if state == setSuccessInform {
			statusCode, response, err = sendSetSuccessInformRequest(nonce)
		} else if state == requestedParams {
			statusCode, response, err = sendRequestedParamsRequest(nonce, macAddress)
		} else if state == emptyInform {
			statusCode, response, err = sendEmptyInformRequest(nonce)
		}

		if err != nil {
			fmt.Printf("[-] Error during request: %s\n", err.Error())
			return
		}

		if statusCode == 204 {
			fmt.Printf("[+] 204 No Content received. Nothing to do...\n")
			return
		}

		if statusCode != 200 {
			fmt.Printf("[-] Unexpected status code(%d) returned\n", statusCode)
			return
		}

		responseType, xml, err := cwmp.ParseResponse(response)
		if err != nil {
			fmt.Printf("[-] Unknown or unsupported response: %s\n", err.Error())
		}

		nonce = xml.Header.CwmpId

		if responseType == cwmp.GetParamRequest {

			state = requestedParams
		} else if responseType == cwmp.SetParamRequest {

			state = setSuccessInform
		} else {

			state = emptyInform
		}
	}

}

func RunCWMPEngine(serial string, macAddr string, extIP string) {
	serialNo = serial
	macAddress = macAddr
	externalIP = extIP

	sess = session.NewSession()

	go startChain(initialInform)
}
