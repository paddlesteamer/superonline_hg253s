package cwmp

import (
	"encoding/xml"
	"fmt"
)

const (
	ConnectionRequestUsernameField = "InternetGatewayDevice.ManagementServer.ConnectionRequestUsername"
	ConnectionRequestPasswordField = "InternetGatewayDevice.ManagementServer.ConnectionRequestPassword"
	MACAddressField                = "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.MACAddress"
	ManagementServerURLField       = "InternetGatewayDevice.ManagementServer.URL"
	ManagementServerUsernameField  = "InternetGatewayDevice.ManagementServer.Username"
	ManagementServerPasswordField  = "InternetGatewayDevice.ManagementServer.Password"
	PeriodicInformIntervalField    = "InternetGatewayDevice.ManagementServer.PeriodicInformInterval"
)

type ResponseType int

const (
	GetParamRequest = iota
	SetParamRequest = iota
	InformRequest   = iota
)

type Envelope struct {
	XMLName xml.Name `xml:"Envelope"`
	Header  Header
	Body    Body
}

type Header struct {
	XMLName xml.Name `xml:"Header"`
	CwmpId  string   `xml:"ID"`
}

type Body struct {
	XMLName            xml.Name `xml:"Body"`
	SetParameterValues SetParameterValues
	GetParameterValues GetParameterValues
}

type SetParameterValues struct {
	XMLName       xml.Name `xml:"SetParameterValues"`
	ParameterList ParameterList
}

type ParameterList struct {
	XMLName    xml.Name         `xml:"ParameterList"`
	Parameters []ParameterValue `xml:"ParameterValueStruct"`
}

type ParameterValue struct {
	XMLName xml.Name `xml:"ParameterValueStruct"`
	Name    string   `xml:"Name"`
	Value   string   `xml:"Value"`
}

type GetParameterValues struct {
	XMLName        xml.Name `xml:"GetParameterValues"`
	ParameterNames ParameterNames
}

type ParameterNames struct {
	XMLName xml.Name `xml:"ParameterNames"`
	Name    []string `xml:"string"`
}

func ParseResponse(payload []byte) (ResponseType, Envelope, error) {
	res := Envelope{}

	err := xml.Unmarshal(payload, &res)
	if err != nil {
		return 0, res, fmt.Errorf("Error while parsing xml data: %s", err.Error())
	}

	if len(res.Body.GetParameterValues.ParameterNames.Name) > 0 {
		return GetParamRequest, res, nil
	}

	if len(res.Body.SetParameterValues.ParameterList.Parameters) > 0 {
		return SetParamRequest, res, nil
	}

	return InformRequest, res, nil
}
