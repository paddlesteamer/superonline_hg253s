package session

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

type Session struct {
	Cookies []string
}

func NewSession() *Session {
	return &Session{Cookies: make([]string, 0)}
}

func (s *Session) SendRequest(payload []byte) (int, []byte, error) {
	client := http.Client{}

	req, err := http.NewRequest("POST", "http://acs.superonline.net:8015/cwmpWeb/WGCPEMgt", bytes.NewBuffer(payload))
	if err != nil {
		return 0, nil, fmt.Errorf("Error while creating http request: %s", err.Error())
	}

	req.Header.Add("User-Agent", "HW_ATP_HTTP")
	req.Header.Add("SOAPAction", "")
	req.Header.Set("Content-type", "text/xml; charset=UTF-8")

	if len(s.Cookies) > 0 {
		req.Header.Add("Cookie", strings.Join(s.Cookies, ";"))
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("Error while doing http request: %s", err.Error())
	}
	defer resp.Body.Close()

	for _, cookie := range resp.Header["Set-Cookie"] {
		s.Cookies = append(s.Cookies, cookie)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, fmt.Errorf("Error while reading response body: %s", err.Error())
	}

	return resp.StatusCode, body, nil
}
