package main

import (
	"os"
)

func main() {

	args := os.Args[1:]

	serial := args[0]
	macAddr := args[1]
	extIP := args[2]

	cwmpCh := make(chan CRAccount)
	conReqAccCh := make(chan CRAccount)
	conReqCh := make(chan bool)

	go RunCWMPEngine(cwmpCh, serial, macAddr, extIP)
	go RunCRServer(conReqAccCh, conReqCh)

	for {
		select {
		case acc := <-cwmpCh:
			conReqAccCh <- acc
		case <-conReqCh:
			CWMPConnectImmediately()
		}
	}
}
