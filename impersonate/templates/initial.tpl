<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:cwmp="urn:dslforum-org:cwmp-1-0">
<SOAP-ENV:Header>
<cwmp:ID SOAP-ENV:mustUnderstand="1">%NONCE%</cwmp:ID>
</SOAP-ENV:Header>
<SOAP-ENV:Body>
<cwmp:Inform>
<DeviceId>
<Manufacturer>Huawei</Manufacturer>
<OUI>00E0FC</OUI>
<ProductClass>HG253s</ProductClass>
<SerialNumber>%SERIAL%</SerialNumber>
</DeviceId>
<Event SOAP-ENC:arrayType="cwmp:EventStruct[3]">
<EventStruct>
<EventCode>4 VALUE CHANGE</EventCode>
<CommandKey/>
</EventStruct>
<EventStruct>
<EventCode>1 BOOT</EventCode>
<CommandKey/>
</EventStruct>
<EventStruct>
<EventCode>0 BOOTSTRAP</EventCode>
<CommandKey/>
</EventStruct>
</Event>
<MaxEnvelopes>1</MaxEnvelopes>
<CurrentTime>2010-01-01T00:01:26</CurrentTime>
<RetryCount>0</RetryCount>
<ParameterList SOAP-ENC:arrayType="cwmp:ParameterValueStruct[8]">
<ParameterValueStruct>
<Name>InternetGatewayDevice.DeviceSummary</Name>
<Value xsi:type="xsd:string">InternetGatewayDevice:1.1[](Baseline:1, EthernetLAN:1, USBLAN:1, WiFiLAN:1, EthernetWAN:1, Bridging:1, Time:1, IPPing:1, DeviceAssociation:1, UDPConnReq:1)</Value>
</ParameterValueStruct>
<ParameterValueStruct>
<Name>InternetGatewayDevice.DeviceInfo.ProvisioningCode</Name>
<Value xsi:type="xsd:string"/>
</ParameterValueStruct>
<ParameterValueStruct>
<Name>InternetGatewayDevice.DeviceInfo.SpecVersion</Name>
<Value xsi:type="xsd:string">1.0</Value>
</ParameterValueStruct>
<ParameterValueStruct>
<Name>InternetGatewayDevice.DeviceInfo.HardwareVersion</Name>
<Value xsi:type="xsd:string">VER.A</Value>
</ParameterValueStruct>
<ParameterValueStruct>
<Name>InternetGatewayDevice.DeviceInfo.SoftwareVersion</Name>
<Value xsi:type="xsd:string">HG253sC01B035</Value>
</ParameterValueStruct>
<ParameterValueStruct>
<Name>InternetGatewayDevice.ManagementServer.ParameterKey</Name>
<Value xsi:type="xsd:string"/>
</ParameterValueStruct>
<ParameterValueStruct>
<Name>InternetGatewayDevice.ManagementServer.ConnectionRequestURL</Name>
<Value xsi:type="xsd:string">http://%IP%:4050/connectionRequest</Value>
</ParameterValueStruct>
<ParameterValueStruct>
<Name>InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.ExternalIPAddress</Name>
<Value xsi:type="xsd:string">%IP%</Value>
</ParameterValueStruct>
</ParameterList>
</cwmp:Inform>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>
