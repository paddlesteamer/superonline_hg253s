<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:cwmp="urn:dslforum-org:cwmp-1-0">
<SOAP-ENV:Header>
<cwmp:ID SOAP-ENV:mustUnderstand="1">null1</cwmp:ID>
</SOAP-ENV:Header>
<SOAP-ENV:Body>
<cwmp:GetParameterValuesResponse>
<ParameterList SOAP-ENC:arrayType="cwmp:ParameterValueStruct[1]">
<ParameterValueStruct>
<Name>InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.MACAddress</Name>
<Value xsi:type="xsd:string">%MAC%</Value>
</ParameterValueStruct>
</ParameterList>
</cwmp:GetParameterValuesResponse>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>
