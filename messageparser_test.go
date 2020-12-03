package ciscoiselogparser

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseMessageCSV(t *testing.T) {

	tc := []struct {
		name            string
		log             string
		expectedMarshal []byte
		expectedError   error
	}{
		{
			name:            "Golden Path",
			log:             `3002 NOTICE Radius-Accounting: RADIUS Accounting watchdog update, UnexpectedValue=MrFreeze, Device IP Address=86.75.30.9, UserName=bwayne, RequestLatency=13, textEncodedORAddress=\{"devices": [\{"deviceid": "12345"\, "mac": ["a1-b2-c3-d4-e5-f6"]\}]\}, User-Name=bwayne, NAS-IP-Address=86.75.30.9, NAS-Port=1234567, Service-Type=Framed, Framed-Protocol=PPP, Framed-IP-Address=86.75.30.9, Class=BYODPolicy, Called-Station-ID=86.75.30.9, Calling-Station-ID=86.75.30.9, Acct-Status-Type=Interim-Update, Acct-Delay-Time=0, Acct-Input-Octets=142933, Acct-Output-Octets=368173, Acct-Authentic=RADIUS, Acct-Input-Packets=1255, Acct-Output-Packets=999, NAS-Port-Type=Virtual, Tunnel-Client-Endpoint=(tag=0) 86.75.30.9, cisco-av-pair=mdm-tlv=device-platform=win, cisco-av-pair=mdm-tlv=device-mac=a1-b2-c3-d4-e5-f6, cisco-av-pair=audit-session-id=0a4012b20a59a0005f99afba, cisco-av-pair=mdm-tlv=device-platform-version=10.0.19041 , cisco-av-pair=mdm-tlv=device-public-mac=a1-b2-c3-d4-e5-f6, cisco-av-pair=mdm-tlv=ac-user-agent=AnyConnect Windows 4.6.01098, cisco-av-pair=mdm-tlv=device-type=Gigabyte Technology Co.\, Ltd. X570 AORUS ELITE, cisco-av-pair=mdm-tlv=device-uid=1ab2c3, IsMachineAuthentication=false, IsMachineIdentity=true, CVPN3000/ASA/PIX7x-Tunnel-Group-Name=byod, CVPN3000/ASA/PIX7x-Client-Type=2, CVPN3000/ASA/PIX7x-Session-Type=1, CVPN3000/ASA/PIX7x-Session-Subtype=3, SelectedAccessService=PAP-ALLOWED-PROTOCOLS, Step=11004, Step=11017, Step=15049, Step=15008, Step=15048, Step=22094, Step=11005, NetworkDeviceGroups=Security#Security#High-Security, NetworkDeviceGroups=Location#All Locations#SC#SC1, NetworkDeviceGroups=Device Type#All Device Types#Cisco#Firewall, NetworkDeviceGroups=IPSEC#Is IPSEC Device#No, NetworkDeviceGroups=Team#Team#Justice League, NetworkDeviceGroups=Role#Role, Security=Security#Security#High-Security, Network Device Profile=Cisco, Location=Location#All Locations#SC#SC1, Device Type=Device Type#All Device Types#Cisco#Firewall, IPSEC=IPSEC#Is IPSEC Device#No, Team=Team#Team#Justice League, #015`,
			expectedMarshal: []byte(`{"AcctAuthentic":"RADIUS","AcctDelayTime":"0","AcctInputOctets":"142933","AcctInputPackets":"1255","AcctOutputOctets":"368173","AcctOutputPackets":"999","AcctStatusType":"Interim-Update","CVPN3000ASAPIX7xClientType":"2","CVPN3000ASAPIX7xSessionSubtype":"3","CVPN3000ASAPIX7xSessionType":"1","CVPN3000ASAPIX7xTunnelGroupName":"byod","CalledStationID":["86.75.30.9"],"CallingStationID":["86.75.30.9"],"CiscoAVPair":{"MDMTLV":{"DevicePlatform":"win","DevicePlatformVersion":"10.0.19041 ","DeviceMAC":"a1-b2-c3-d4-e5-f6","DevicePublicMAC":"a1-b2-c3-d4-e5-f6","DeviceType":"Gigabyte Technology Co., Ltd. X570 AORUS ELITE","DeviceUID":"1ab2c3","ACUserAgent":"AnyConnect Windows 4.6.01098"},"AuditSessionID":"0a4012b20a59a0005f99afba"},"Class":["BYODPolicy"],"DeviceIPAddress":"86.75.30.9","DeviceType":{"Value":"All Device Types","Child":{"Value":"Cisco","Child":{"Value":"Firewall"}}},"EventDescription":"RADIUS Accounting watchdog update","EventType":3002,"FramedIPAddress":"86.75.30.9","FramedProtocol":"PPP","IPSEC":{"Value":"Is IPSEC Device","Child":{"Value":"No"}},"IsMachineAuthentication":false,"IsMachineIdentity":true,"Location":{"Value":"All Locations","Child":{"Value":"SC","Child":{"Value":"SC1"}}},"NASIPAddress":"86.75.30.9","NASPort":"1234567","NASPortType":"Virtual","NetworkDeviceProfile":"Cisco","NetworkDeviceGroups":{"Device Type":{"Value":"All Device Types","Child":{"Value":"Cisco","Child":{"Value":"Firewall"}}},"IPSEC":{"Value":"Is IPSEC Device","Child":{"Value":"No"}},"Location":{"Value":"All Locations","Child":{"Value":"SC","Child":{"Value":"SC1"}}},"Role":{"Value":"Role"},"Security":{"Value":"Security","Child":{"Value":"High-Security"}},"Team":{"Value":"Team","Child":{"Value":"Justice League"}}},"RequestLatency":13,"Security":{"Value":"Security","Child":{"Value":"High-Security"}},"SelectedAccessService":"PAP-ALLOWED-PROTOCOLS","ServiceType":"Framed","Step":["11004","11017","15049","15008","15048","22094","11005"],"Team":{"Value":"Team","Child":{"Value":"Justice League"}},"TextEncodedORAddress":{"devices":[{"deviceid":"12345","mac":["a1-b2-c3-d4-e5-f6"]}]},"TunnelClientEndpoint":"(tag=0) 86.75.30.9","UserName":"bwayne","MessageDetails":{"UnexpectedFields":{"UnexpectedValue":"MrFreeze"}}}`),
			expectedError:   nil,
		},
		{
			name:            "Malformed Message Log",
			log:             `RADIUS Accounting watchdog update`,
			expectedMarshal: []byte(`{"MessageDetails":{"UnexpectedFields":{}}}`),
			expectedError:   &ParseError{},
		},
		{
			name:            "Wrong type for field - int",
			log:             `3002 NOTICE Radius-Accounting: RADIUS Accounting watchdog update, RequestLatency=NotANumber`,
			expectedMarshal: []byte(`{"EventDescription":"RADIUS Accounting watchdog update","EventType":3002,"MessageDetails":{"UnexpectedFields":{}}}`),
			expectedError:   &ParseError{},
		},
		{
			name:            "Wrong type for field - bool",
			log:             `3002 NOTICE Radius-Accounting: RADIUS Accounting watchdog update, IsMachineAuthentication=NotABool`,
			expectedMarshal: []byte(`{"EventDescription":"RADIUS Accounting watchdog update","EventType":3002,"MessageDetails":{"UnexpectedFields":{}}}`),
			expectedError:   &ParseError{},
		},
		{
			name:            "Wrong type for field - DropDown",
			log:             `3002 NOTICE Radius-Accounting: RADIUS Accounting watchdog update, Team=NotADropDown`,
			expectedMarshal: []byte(`{"EventDescription":"RADIUS Accounting watchdog update","EventType":3002,"MessageDetails":{"UnexpectedFields":{}}}`),
			expectedError:   &ParseError{},
		},
		{
			name:            "Wrong type for field - CiscoAVPair",
			log:             `3002 NOTICE Radius-Accounting: RADIUS Accounting watchdog update, cisco-av-pair=NotACiscoAVPair`,
			expectedMarshal: []byte(`{"CiscoAVPair":{},"EventDescription":"RADIUS Accounting watchdog update","EventType":3002,"MessageDetails":{"UnexpectedFields":{}}}`),
			expectedError:   &ParseError{},
		},
		{
			name:            "Wrong type for field - MDMTLV",
			log:             `3002 NOTICE Radius-Accounting: RADIUS Accounting watchdog update, cisco-av-pair=mdm-tlv=NotAnMDMTLV`,
			expectedMarshal: []byte(`{"CiscoAVPair":{},"EventDescription":"RADIUS Accounting watchdog update","EventType":3002,"MessageDetails":{"UnexpectedFields":{}}}`),
			expectedError:   &ParseError{},
		},
		{
			name:            "Wrong type for field - TextEncodedORAddress",
			log:             `3002 NOTICE Radius-Accounting: RADIUS Accounting watchdog update, textEncodedORAddress=NotATextEncodedORAddress`,
			expectedMarshal: []byte(`{"EventDescription":"RADIUS Accounting watchdog update","EventType":3002,"MessageDetails":{"UnexpectedFields":{}}}`),
			expectedError:   &ParseError{},
		},
		{
			name:            "Wrong type for field - DropDownMap",
			log:             `3002 NOTICE Radius-Accounting: RADIUS Accounting watchdog update, NetworkDeviceGroups=NotADropDownMap`,
			expectedMarshal: []byte(`{"EventDescription":"RADIUS Accounting watchdog update","EventType":3002,"MessageDetails":{"UnexpectedFields":{}}}`),
			expectedError:   &ParseError{},
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			var output LogMessage
			err := ParseMessageCSV(tt.log, &output)
			bytes, _ := json.Marshal(output)

			assert.IsType(t, tt.expectedError, err, fmt.Sprintf("Error: %v", err))
			assert.Equal(t, tt.expectedMarshal, bytes, fmt.Sprintf("Expected json: %s\n\n does not match actual json: %s", string(tt.expectedMarshal), string(bytes)))
		})
	}
}

func TestDropDown(t *testing.T) {

	tc := []struct {
		name           string
		testFn         func(DropDown) interface{}
		expectedOutput interface{}
	}{
		{
			name: "Get String",
			testFn: func(d DropDown) interface{} {
				return d.String()
			},
			expectedOutput: "First -> Second -> Third",
		},
		{
			name: "Get Slice",
			testFn: func(d DropDown) interface{} {
				return d.Slice()
			},
			expectedOutput: []string{"First", "Second", "Third"},
		},
		{
			name: "Get Last",
			testFn: func(d DropDown) interface{} {
				return d.Last()
			},
			expectedOutput: "Third",
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			d := DropDown{
				Value: "First",
				Child: &DropDown{
					Value: "Second",
					Child: &DropDown{
						Value: "Third",
					},
				},
			}
			assert.Equal(t, tt.expectedOutput, tt.testFn(d))
		})
	}
}

func TestDropDownMap(t *testing.T) {

	tc := []struct {
		name           string
		input          DropDownMap
		expectedOutput []string
	}{
		{
			name: "Get String - Golden Path",
			input: DropDownMap{
				"A": DropDown{
					Value: "First",
					Child: &DropDown{
						Value: "Second",
						Child: &DropDown{
							Value: "Third",
						},
					},
				},
				"B": DropDown{
					Value: "Fourth",
					Child: &DropDown{
						Value: "Fifth",
						Child: &DropDown{
							Value: "Sixth",
						},
					},
				},
			},
			expectedOutput: []string{"A: First -> Second -> Third", "B: Fourth -> Fifth -> Sixth"},
		},
		{
			name:           "Get String - Empty Map",
			input:          DropDownMap{},
			expectedOutput: []string{"{}"},
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			output := tt.input.String()
			for _, expected := range tt.expectedOutput {
				assert.Contains(t, output, expected)
			}
		})
	}
}

func TestParseIseLogEventValueNotAnInt(t *testing.T) {
	assert.Equal(t, &TypeMismatch{
		Original: "NotAnInt",
		Type:     "int",
	}, parseIseLogEventValue(&LogMessage{}, "EventType", "NotAnInt"))
}

func TestIseLogEventString(t *testing.T) {
	tc := []struct {
		name            string
		input           IseLogEvent
		expectedOutput  string
		expectedReverse IseLogEvent
	}{
		{
			name:            "Golden Path",
			input:           IseLogEvent(5200),
			expectedOutput:  "5200 NOTICE Passed-Authentication",
			expectedReverse: IseLogEvent(5200),
		},
		{
			name:            "Invalid Event Type",
			input:           IseLogEvent(7),
			expectedOutput:  "",
			expectedReverse: IseLogEvent(0),
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectedOutput, tt.input.String())
			assert.Equal(t, tt.expectedReverse, StrToIseLogEvent(tt.input.String()))
		})
	}
}

func TestSetField(t *testing.T) {

	tc := []struct {
		name          string
		object        interface{}
		field         string
		value         interface{}
		expectedError error
	}{
		{
			name: "Wrong field type",
			object: struct {
				Test   string
				hidden string
			}{},
			field:         "Test",
			value:         1,
			expectedError: &AssignmentFailure{},
		},
		{
			name: "Field cannot be set",
			object: struct {
				Test   string
				hidden string
			}{},
			field:         "hidden",
			value:         "test",
			expectedError: &AssignmentFailure{},
		},
		{
			name: "Field does not exist",
			object: struct {
				Test   string
				hidden string
			}{},
			field:         "unknown",
			value:         "test",
			expectedError: &AssignmentFailure{},
		},
		{
			name:          "Object is not a struct",
			object:        "notAStruct",
			field:         "unknown",
			value:         "test",
			expectedError: &AssignmentFailure{},
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {

			testObject, ok := tt.object.(struct {
				Test   string
				hidden string
			})
			if ok {
				assert.IsType(t, tt.expectedError, setField(&testObject, tt.field, tt.value))
			} else {
				assert.IsType(t, tt.expectedError, setField(&tt.object, tt.field, tt.value))

			}
		})
	}
}

func TestAppendToSlice(t *testing.T) {

	tc := []struct {
		name          string
		object        interface{}
		field         string
		value         interface{}
		expectedError error
	}{
		{
			name: "Wrong field type",
			object: struct {
				Test   string
				hidden string
			}{},
			field:         "Test",
			value:         []string{"Test"},
			expectedError: &AssignmentFailure{},
		},
		{
			name: "Field cannot be set",
			object: struct {
				Test   string
				hidden string
			}{},
			field:         "hidden",
			value:         "test",
			expectedError: &AssignmentFailure{},
		},
		{
			name: "Field does not exist",
			object: struct {
				Test   string
				hidden string
			}{},
			field:         "unknown",
			value:         "test",
			expectedError: &AssignmentFailure{},
		},
		{
			name:          "Object is not a struct",
			object:        "notAStruct",
			field:         "unknown",
			value:         "test",
			expectedError: &AssignmentFailure{},
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {

			testObject, ok := tt.object.(struct {
				Test   string
				hidden string
			})
			if ok {
				assert.IsType(t, tt.expectedError, appendToSlice(&testObject, tt.field, tt.value))
			} else {
				assert.IsType(t, tt.expectedError, appendToSlice(&tt.object, tt.field, tt.value))

			}
		})
	}
}

func TestAddToMap(t *testing.T) {

	tc := []struct {
		name          string
		object        interface{}
		field         string
		value         interface{}
		expectedError error
	}{
		{
			name: "Wrong field type",
			object: struct {
				Test   string
				hidden string
			}{},
			field:         "Test",
			value:         []string{"Test"},
			expectedError: &AssignmentFailure{},
		},
		{
			name: "Field cannot be set",
			object: struct {
				Test   string
				hidden string
			}{},
			field:         "hidden",
			value:         "test",
			expectedError: &AssignmentFailure{},
		},
		{
			name: "Field does not exist",
			object: struct {
				Test   string
				hidden string
			}{},
			field:         "unknown",
			value:         "test",
			expectedError: &AssignmentFailure{},
		},
		{
			name:          "Object is not a struct",
			object:        "notAStruct",
			field:         "unknown",
			value:         "test",
			expectedError: &AssignmentFailure{},
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {

			testObject, ok := tt.object.(struct {
				Test   string
				hidden string
			})
			if ok {
				assert.IsType(t, tt.expectedError, addToMap(&testObject, tt.field, "key", tt.value))
			} else {
				assert.IsType(t, tt.expectedError, addToMap(&tt.object, tt.field, "key", tt.value))
			}
		})
	}
}

func TestGetFieldTypeNotAnObject(t *testing.T) {
	notAnObject := "Test"
	fieldType := getFieldType(&notAnObject, "Test")
	assert.Nil(t, fieldType)
}

func TestAssignmentFailureString(t *testing.T) {
	a := AssignmentFailure{
		Message: "assignment-failure",
		Reason:  "failed to assign stuff",
	}
	assert.Equal(t, "assignment-failure: failed to assign value during message parsing: failed to assign stuff", a.Error())
}
