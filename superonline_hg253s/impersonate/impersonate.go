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
	go RunCWMPEngine(cwmpCh, serial, macAddr, extIP)
}
