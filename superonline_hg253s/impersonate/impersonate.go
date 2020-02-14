package main

import (
	"fmt"
	"impersonate/session"
	"os"
)

func main() {

	args := os.Args[1:]

	serial := args[0]
	macAddr := args[1]
	extIP := args[2]

	session := session.NewSession()

	reqBody, err := GenerateInitialRequestBody(serial, extIP)
	if err != nil {
		fmt.Printf("[-] Error while generating intial request body: %s\n", reqBody)
		return
	}

	statusCode, respBody, err := session.SendRequest(reqBody)
	if err != nil {
		fmt.Printf("[-] Error during initial request: %s\n", err.Error())
	}

}
