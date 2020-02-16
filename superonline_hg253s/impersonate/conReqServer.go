package main

import (
	"crypto/md5"
	"fmt"
	"io"
	"net/http"

	auth "github.com/abbot/go-http-auth"
)

var (
	account = CRAccount{Username: "", Password: ""}

	conReqCh chan bool
)

func secret(user string, realm string) string {
	if user == account.Username {
		return account.Password
	}

	return ""
}

func handle(w http.ResponseWriter, r *auth.AuthenticatedRequest) {
	fmt.Printf("[+] New connection request!\n")
	conReqCh <- true
}

func RunCRServer(confCh chan CRAccount, conReqCh chan bool) {
	authenticator := auth.NewDigestAuthenticator("HuaweiHomeGateway", secret)
	http.HandleFunc("/connectionRequest", authenticator.Wrap(handle))

	http.ListenAndServe(":4050", nil)

	for {
		account = <-confCh

		fmt.Printf("[+] New account details: %s:%s\n", account.Username, account.Password)

		h := md5.New()
		io.WriteString(h, account.Password)
		account.Password = fmt.Sprintf("%x", h.Sum(nil))

	}
}
