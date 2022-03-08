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
			name:            "Golden Path - 80002 event Host",
			log:             `80002 INFO Profiler: Profiler EndPoint profiling event occurred, ConfigVersionId=50, EndpointCertainityMetric=50, EndpointMacAddress=00:aa:11:bb:22:cc, EndpointMatchedPolicy=Macintosh-Workstation,EndpointOUI=REALTEK SEMICONDUCTOR CORP., EndpointPolicy=Macintosh-Workstation, EndpointProperty=AuthenticationIdentityStore=office.company.com\\,AD-User-Candidate-Identities=user@office.com\\,AuthenticationMethod=PAP_ASCII\\,Security=Security#Security#High-Security\\,User-Fetch-StreetAddress=\\,SelectedAccessService=PAP-ALLOWED-PROTOCOLS\\,device-type=MacBookPro17\\,1\\,User-Fetch-Job-Title=Title\\,MessageCode=3001\\,SelectedAuthenticationIdentityStores=office.com\\,Device Type=Device Type#All Device Types#Cisco#Firewall\\,User-Fetch-Last-Name=Lastname\\,User-Fetch-Telephone=\\,AuthenticationStatus=AuthenticationPassed\\,Software Version=Unknown\\,NetworkDeviceGroups=Security#Security#High-Security\\, Device Type#All Device Types#Cisco#Firewall\\, IPSEC#Is IPSEC Device#No\\, Team#Team#Core Network and Automation\\, Location#All Locations\\, Role#Role\\,BYODRegistration=Unknown\\,IdentitySelectionMatchedRule=Default\\,OriginalUserName=uername\\,Total Certainty Factor=50\\,IdentityGroupID=12345-ABCD\\,AD-User-Resolved-Identities=username@office.com\\,employeeID=111111\\,NAS-Port-Type=Virtual\\,DeviceRegistrationStatus=NotRegistered\\,Team=Team#Team#Core Network and Automation\\,User-Fetch-Email=user@office.com\\,IPSEC=IPSEC#Is IPSEC Device#No\\,User-Fetch-CountryName=\\,IdentityPolicyMatchedRule=Default\\,Name=Endpoint Identity Groups:Trusted\\,IsMachineIdentity=false\\,StaticAssignment=false\\,User-Name=username\\,User-Fetch-First-Name=username\\,IdentityAccessRestricted=false\\,sAMAccountName=username\\,User-Fetch-User-Name=username\\,IsThirdPartyDeviceFlow=false\\,device-platform=mac-intel\\,Device IP Address=100.111.111\\,PortalUser=\\,AllowedProtocolMatchedRule=Default\\,Role=Role#Role\\,FailureReason=-\\,textEncodedORAddress=\\\\\"devices\": [\\\\\"deviceid\": \"deviceid\"\\\\ \"mac\": [\"aa:11:bb:22:33\"\\\\ \"aa:11:bb:22:33\"\\\\ \"aa:11:bb:22:33\"\\\\ \"aa:11:bb:22:33\"\\\\ \"aa:11:bb:22:33\"\\"]\\\\]\\\\FeedService=false\\,SelectedAuthorizationProfiles=Policy\\,host-name=thisisahostname\\,Response=\\{Class=Policy\\; Class=AAAA:aaaa:aa1-aaaaaa/00000000/0000000\\; cisco-av-pair=profile-name=Macintosh-Workstation\\; LicenseTypes=1\\; \\}UserAccountControl=000\\,Framed-IP-Address=\\,IsMachineAuthentication=false\\,AuthorizationPolicyMatchedRule=Policy\\,Location=Location#All Locations\\,username=username\\,UniqueSubjectID=, EndpointSourceEvent=RADIUS Probe, EndpointIdentityGroup=Trusted, ProfilerServer=office.com, #015`,
			expectedMarshal: []byte(`{"ConfigVersionID":"50","EndpointCertainityMetric":"50","EndpointIdentityGroup":"Trusted","EndPointMACAddress":"00:aa:11:bb:22:cc","EndpointMatchedPolicy":"Macintosh-Workstation,EndpointOUI=REALTEK SEMICONDUCTOR CORP.","EndpointPolicy":"Macintosh-Workstation","EndpointProperty":{"ADUserCandidateIdentities":"user@office.com","ADUserResolvedIdentities":"username@office.com","AuthenticationIdentityStore":"office.company.com","AuthenticationMethod":"PAP_ASCII","AuthenticationStatus":"AuthenticationPassed","AuthorizationPolicyMatchedRule":"Policy","DeviceIPAddress":"100.111.111","DeviceRegistrationStatus":"NotRegistered","DeviceType":{"Value":"All Device Types","Child":{"Value":"Cisco","Child":{"Value":"Firewall"}}},"EmployeeID":"111111","FailureReason":"-","FramedIPAddress":"","Hostname":"thisisahostname","IPSEC":{"Value":"Is IPSEC Device","Child":{"Value":"No"}},"IdentityAccessRestricted":"false","IdentityPolicyMatchedRule":"Default","IdentitySelectionMatchedRule":"Default","IsMachineAuthentication":false,"IsMachineIdentity":false,"IsThirdPartyDeviceFlow":false,"Location":{"Value":"All Locations"},"NASPortType":"Virtual","Name":"Endpoint Identity Groups:Trusted","NetworkDeviceGroups":{"Security":{"Value":"Security","Child":{"Value":"High-Security"}}},"OriginalUserName":"uername","Response":{"MessageDetails":{"UnexpectedFields":{"\\\\":""}}},"Role":{"Value":"Role"},"SAMAccountName":"username","Security":{"Value":"Security","Child":{"Value":"High-Security"}},"SelectedAccessService":"PAP-ALLOWED-PROTOCOLS","SelectedAuthenticationIdentityStores":"office.com","SelectedAuthorizationProfiles":"Policy","SoftwareVersion":"Unknown","Team":{"Value":"Team","Child":{"Value":"Core Network and Automation"}},"UserName":"username","MessageDetails":{"UnexpectedFields":{" Device Type#All Device Types#Cisco#Firewall":""," IPSEC#Is IPSEC Device#No":""," Location#All Locations":""," Role#Role":""," Team#Team#Core Network and Automation":"","1":"","AllowedProtocolMatchedRule":"Default","BYODRegistration":"Unknown","IdentityGroupID":"12345-ABCD","MessageCode":"3001","PortalUser":"","StaticAssignment":"false","Total Certainty Factor":"50","UniqueSubjectID":"","User-Fetch-CountryName":"","User-Fetch-Email":"user@office.com","User-Fetch-First-Name":"username","User-Fetch-Job-Title":"Title","User-Fetch-Last-Name":"Lastname","User-Fetch-StreetAddress":"","User-Fetch-Telephone":"","User-Fetch-User-Name":"username","device-platform":"mac-intel","username":"username"}}},"EndpointSourceEvent":"RADIUS Probe","EventDescription":"Profiler EndPoint profiling event occurred","EventType":80002,"ProfilerServer":"office.com","MessageDetails":{"UnexpectedFields":{}}}`),
			expectedError:   nil,
		},
		{
			name:            "Golden Path - 80002 event PAP",
			log:             `80002 INFO Profiler: Profiler EndPoint profiling event occurred, ConfigVersionId=50, EndpointCertainityMetric=50, EndpointMacAddress=00:aa:11:bb:22:cc, EndpointMatchedPolicy=Macintosh-Workstation,EndpointOUI=REALTEK SEMICONDUCTOR CORP., EndpointPolicy=Macintosh-Workstation, EndpointProperty=AuthenticationIdentityStore=office.com\\,AD-User-Candidate-Identities=usern@office.com\\,AuthenticationMethod=PAP_ASCII\\,Security=Security#Security#High-Security\\,User-Fetch-StreetAddress=\\,SelectedAccessService=PAP-ALLOWED-PROTOCOLS\\,device-type=MacBookPro17\\,1\\,User-Fetch-Job-Title=Job title\\,NAS-Port=000000\\,DestinationIPAddress=111.11.1111.111\\,MessageCode=3001\\,SelectedAuthenticationIdentityStores=office.com\\,AD-User-SamAccount-Name=office\\,Device Type=Device Type#All Device Types#Cisco#Firewall\\,User-Fetch-Last-Name=Lastname\\,User-Fetch-Telephone=\\,AuthenticationStatus=AuthenticationPassed\\,Software Version=Unknown\\,NetworkDeviceGroups=Security#Security#High-Security\\, Device Type#All Device Types#Cisco#Firewall\\, IPSEC#Is IPSEC Device#No\\, Team#Team#Core Network and Automation\\, Location#All Locations\\, Role#Role\\,BYODRegistration=Unknown\\,IdentitySelectionMatchedRule=Default\\,OriginalUserName=username\\,Total Certainty Factor=50\\,IdentityGroupID=00\\,,AD-User-Resolved-Identities=username@office.com\\,employeeID=111111\\,NAS-Port-Type=Virtual\\,StepData=4= Normalised Radius.RadiusFlowType (4 times)\\,DeviceRegistrationStatus=NotRegistered\\,Team=Team#Team#Core Network and Automation\\,User-Fetch-Email=user@office.com\\,PolicyVersion=00\,CVPN3000/ASA/PIX7x-Session-Subtype=3\\,,EndPointPolicyID=000\\,User-Fetch-CountryName=\\,FirstCollection=00\\,CacheUpdateTime=00\\,IdentityPolicyMatchedRule=Default\\,Name=Endpoint Identity Groups:Trusted\\,IsMachineIdentity=false\\,StaticAssignment=false\\,User-Name=username\\,User-Fetch-First-Name=Firstname\\,IdentityAccessRestricted=false\\,sAMAccountName=username\\,User-Fetch-User-Name=username\\,IsThirdPartyDeviceFlow=false\\,device-platform=mac-intel\\,Device IP Address=111.111.111\\,PortalUser=\\,AllowedProtocolMatchedRule=Default\\,Role=Role#Role\\,Calling-Station-ID=00001:00:00:00\\,FailureReason=-\\,textEncodedORAddress=\\\\\"devices\": [\\\\\"deviceid\": \"deviceid\"\\\\ \"mac\": [\"aa:11:bb:22:cc:33\"\\\\ \"aa:11:bb:22:cc:33\"\\\\ \"aa:11:bb:22:cc:33\"\\\\ \"aa:11:bb:22:cc:33\"\\\\ \"aa:11:bb:22:cc:33\"\\\\ \"aa:11:bb:22:cc:33\"]\\\\]\\\\FeedService=false\\,SelectedAuthorizationProfiles=VPN-StaffManaged-Policy\\,host-name=thisisahostname\\,Response=\\{Class=StaffManagedPolicy\\; cisco-av-pair=profile-name=Macintosh-Workstation\\; LicenseTypes=1\\; \\}UserAccountControl=000\\,Framed-IP-Address=\\,IsMachineAuthentication=false\\,AuthorizationPolicyMatchedRule=VPN-Staff-Managed-ZT\\,Location=Location#All Locations\\,username=username\\,UniqueSubjectID=, EndpointSourceEvent=RADIUS Probe, EndpointIdentityGroup=Trusted, ProfilerServer=random01.office.com, #015`,
			expectedMarshal: []byte(`{"ConfigVersionID":"50","EndpointCertainityMetric":"50","EndpointIdentityGroup":"Trusted","EndPointMACAddress":"00:aa:11:bb:22:cc","EndpointMatchedPolicy":"Macintosh-Workstation,EndpointOUI=REALTEK SEMICONDUCTOR CORP.","EndpointPolicy":"Macintosh-Workstation","EndpointProperty":{"ADUserCandidateIdentities":"usern@office.com","ADUserSamAccountName":"office","AuthenticationIdentityStore":"office.com","AuthenticationMethod":"PAP_ASCII","AuthenticationStatus":"AuthenticationPassed","AuthorizationPolicyMatchedRule":"VPN-Staff-Managed-ZT","CallingStationID":["00001:00:00:00"],"DestinationIPAddress":"111.11.1111.111","DeviceIPAddress":"111.111.111","DeviceRegistrationStatus":"NotRegistered","DeviceType":{"Value":"All Device Types","Child":{"Value":"Cisco","Child":{"Value":"Firewall"}}},"EmployeeID":"111111","FailureReason":"-","FramedIPAddress":"","Hostname":"thisisahostname","IdentityAccessRestricted":"false","IdentityPolicyMatchedRule":"Default","IdentitySelectionMatchedRule":"Default","IsMachineAuthentication":false,"IsMachineIdentity":false,"IsThirdPartyDeviceFlow":false,"Location":{"Value":"All Locations"},"NASPort":"000000","NASPortType":"Virtual","Name":"Endpoint Identity Groups:Trusted","NetworkDeviceGroups":{"Security":{"Value":"Security","Child":{"Value":"High-Security"}}},"OriginalUserName":"username","Response":{"MessageDetails":{"UnexpectedFields":{"\\\\":""}}},"Role":{"Value":"Role"},"SAMAccountName":"username","Security":{"Value":"Security","Child":{"Value":"High-Security"}},"SelectedAccessService":"PAP-ALLOWED-PROTOCOLS","SelectedAuthenticationIdentityStores":"office.com","SelectedAuthorizationProfiles":"VPN-StaffManaged-Policy","SoftwareVersion":"Unknown","StepData":"4= Normalised Radius.RadiusFlowType (4 times)","Team":{"Value":"Team","Child":{"Value":"Core Network and Automation"}},"UserName":"username","MessageDetails":{"UnexpectedFields":{" Device Type#All Device Types#Cisco#Firewall":""," IPSEC#Is IPSEC Device#No":""," Location#All Locations":""," Role#Role":""," Team#Team#Core Network and Automation":"",",AD-User-Resolved-Identities":"username@office.com",",EndPointPolicyID":"000","1":"","AllowedProtocolMatchedRule":"Default","BYODRegistration":"Unknown","CacheUpdateTime":"00","FirstCollection":"00","IdentityGroupID":"00","MessageCode":"3001","PolicyVersion":"00,CVPN3000/ASA/PIX7x-Session-Subtype=3","PortalUser":"","StaticAssignment":"false","Total Certainty Factor":"50","UniqueSubjectID":"","User-Fetch-CountryName":"","User-Fetch-Email":"user@office.com","User-Fetch-First-Name":"Firstname","User-Fetch-Job-Title":"Job title","User-Fetch-Last-Name":"Lastname","User-Fetch-StreetAddress":"","User-Fetch-Telephone":"","User-Fetch-User-Name":"username","device-platform":"mac-intel","username":"username"}}},"EndpointSourceEvent":"RADIUS Probe","EventDescription":"Profiler EndPoint profiling event occurred","EventType":80002,"ProfilerServer":"random01.office.com","MessageDetails":{"UnexpectedFields":{}}}`),
			expectedError:   nil,
		},
		{
			name:            "Golden Path - 80002 event EAP_PEAP",
			log:             `80002 INFO Profiler: Profiler EndPoint profiling event occurred, ConfigVersionId=50, EndpointCertainityMetric=10, EndpointMacAddress=aa:00:bb:11:cc:22, EndpointMatchedPolicy=Apple-Device, EndpointNADAddress=111.11.111, EndpointOUI=Apple\\, Inc., EndpointPolicy=Apple-Device, EndpointProperty=PolicyVersion=32\\,IPSEC=IPSEC#Is IPSEC Device#No\\,RadiusPacketType=Drop\\,NmapScanCount=0\\,SelectedAccessService=EAP-PEAP-ALLOWED-PROTOCOLS\\,PostureExpiry=\\,NetworkDeviceName=networkname\\,NAS-Port=00\\,DestinationIPAddress=1.1.1.1\\,MessageCode=5411\\,Device Type=Device Type#All Device Types#Cisco#WLC\\,Device IP Address=111.11.11.11\\,PortalUser=\\,Role=Role#Role\\,NetworkDeviceGroups=Location#All Locations#SYD#SYD341\\, Device Type#All Device Types#Cisco#WLC\\, IPSEC#Is IPSEC Device#No\\, Security#Security\\, Role#Role\\, Team#Team\\,BYODRegistration=Unknown\\,Total Certainty Factor=10\\,Network Device Profile=Cisco\\,MDMServerID=\\,PostureApplicable=Yes\\,Device Identifier=\\,NAS-Port-Type=Wireless - IEEE 802.11\\,StepData=4= Normalised Radius.RadiusFlowType\\,RegistrationTimeStamp=0\\,TimeToProfile=20\\,PhoneID=\\,DeviceRegistrationStatus=NotRegistered\\,RadiusFlowType=RadiusFlow123\\,Team=Team#Team\\,MatchedPolicyID=1234\\,FeedService=false\\,CreateTime=1646292764687\\,StaticGroupAssignment=false\\,host-name=\\,LastActivity=1234\\,DTLSSupport=Unknown\\,Response=\\{ \\}\\,LastNmapScanTime=0\\,EndPointMACAddress=aa:11:bb:22:cc:33\\,UpdateTime=0\\,UniqueSubjectID=\\,Location=Location#All Locations#LOC#LOC123, EndpointSourceEvent=RADIUS Probe, EndpointIdentityGroup=Profiled, ProfilerServer=office.com, #015`,
			expectedMarshal: []byte(`{"ConfigVersionID":"50","EndpointCertainityMetric":"10","EndpointIdentityGroup":"Profiled","EndPointMACAddress":"aa:00:bb:11:cc:22","EndpointMatchedPolicy":"Apple-Device","EndpointPolicy":"Apple-Device","EndpointNADAddress":"111.11.111","EndpointProperty":{"DTLSSupport":"Unknown","DestinationIPAddress":"1.1.1.1","DeviceIPAddress":"111.11.11.11","DeviceRegistrationStatus":"NotRegistered","DeviceType":{"Value":"All Device Types","Child":{"Value":"Cisco","Child":{"Value":"WLC"}}},"EndPointMACAddress":"aa:11:bb:22:cc:33","Hostname":"","IPSEC":{"Value":"Is IPSEC Device","Child":{"Value":"No"}},"Location":{"Value":"All Locations","Child":{"Value":"LOC","Child":{"Value":"LOC123"}}},"NASPort":"00","NASPortType":"Wireless - IEEE 802.11","NetworkDeviceProfile":"Cisco","NetworkDeviceGroups":{"Location":{"Value":"All Locations","Child":{"Value":"SYD","Child":{"Value":"SYD341"}}}},"NetworkDeviceName":"networkname","RadiusFlowType":"RadiusFlow123","RadiusPacketType":"Drop","Response":{"MessageDetails":{"UnexpectedFields":{"\\\\":""}}},"Role":{"Value":"Role"},"SelectedAccessService":"EAP-PEAP-ALLOWED-PROTOCOLS","StepData":"4= Normalised Radius.RadiusFlowType","Team":{"Value":"Team"},"MessageDetails":{"UnexpectedFields":{" Device Type#All Device Types#Cisco#WLC":""," IPSEC#Is IPSEC Device#No":""," Role#Role":""," Security#Security":""," Team#Team":"","BYODRegistration":"Unknown","CreateTime":"1646292764687","Device Identifier":"","FeedService":"false","LastActivity":"1234","LastNmapScanTime":"0","MDMServerID":"","MatchedPolicyID":"1234","MessageCode":"5411","NmapScanCount":"0","PhoneID":"","PolicyVersion":"32","PortalUser":"","PostureApplicable":"Yes","PostureExpiry":"","RegistrationTimeStamp":"0","StaticGroupAssignment":"false","TimeToProfile":"20","Total Certainty Factor":"10","UniqueSubjectID":"","UpdateTime":"0"}}},"EndpointOUI":"Apple\\, Inc.","EndpointSourceEvent":"RADIUS Probe","EventDescription":"Profiler EndPoint profiling event occurred","EventType":80002,"ProfilerServer":"office.com","MessageDetails":{"UnexpectedFields":{}}}`),
			expectedError:   nil,
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
