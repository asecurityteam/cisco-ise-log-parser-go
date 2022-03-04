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
			name:            "Multiple devices in TextEncodedORAddress",
			log:             `3002 NOTICE Radius-Accounting: RADIUS Accounting watchdog update, textEncodedORAddress=\{"devices": [\{"deviceid": "1234", "mac": ["11-22-33-44-55-66", "aa-bb-cc-dd-ee-ff"]\} \{"deviceid": "abcd", "mac": ["77-88-99-aa-bb-cc", "a1-b2-c3-d4-e5-f6"]\}]\}`,
			expectedMarshal: []byte(`{"EventDescription":"RADIUS Accounting watchdog update","EventType":3002,"TextEncodedORAddress":{"devices":[{"deviceid":"1234","mac":["11-22-33-44-55-66","aa-bb-cc-dd-ee-ff"]},{"deviceid":"abcd","mac":["77-88-99-aa-bb-cc","a1-b2-c3-d4-e5-f6"]}]},"MessageDetails":{"UnexpectedFields":{}}}`),
			expectedError:   nil,
		},
		{
			name:            "Multiple devices in TextEncodedORAddress, but even more broken JSON",
			log:             `3002 NOTICE Radius-Accounting: RADIUS Accounting watchdog update, textEncodedORAddress=\{"devices": [\{"deviceid": "abcd", "mac": ["11-22-33-44-55-66", "aa-bb-cc-dd-ee-ff"]\} \{"deviceid": "efgh", "mac": ["11-22-33-44-55-66", "aa-bb-cc-dd-ee-ff"]\}"deviceid": "ijkl", "mac": ["11-22-33-44-55-66", "aa-bb-cc-dd-ee-ff"]\}"deviceid": "mnop", "mac": ["11-22-33-44-55-66"]\}"deviceid": "qrst", "mac": ["11-22-33-44-55-66", "aa-bb-cc-dd-ee-ff"]\}]\}`,
			expectedMarshal: []byte(`{"EventDescription":"RADIUS Accounting watchdog update","EventType":3002,"TextEncodedORAddress":{"devices":[{"deviceid":"abcd","mac":["11-22-33-44-55-66","aa-bb-cc-dd-ee-ff"]},{"deviceid":"efgh","mac":["11-22-33-44-55-66","aa-bb-cc-dd-ee-ff"]},{"deviceid":"ijkl","mac":["11-22-33-44-55-66","aa-bb-cc-dd-ee-ff"]},{"deviceid":"mnop","mac":["11-22-33-44-55-66"]},{"deviceid":"qrst","mac":["11-22-33-44-55-66","aa-bb-cc-dd-ee-ff"]}]},"MessageDetails":{"UnexpectedFields":{}}}`),
			expectedError:   nil,
		},
		{
			name:            "Wrong type for field - DropDownMap",
			log:             `3002 NOTICE Radius-Accounting: RADIUS Accounting watchdog update, NetworkDeviceGroups=NotADropDownMap`,
			expectedMarshal: []byte(`{"EventDescription":"RADIUS Accounting watchdog update","EventType":3002,"MessageDetails":{"UnexpectedFields":{}}}`),
			expectedError:   &ParseError{},
		},
		{
			name:            "Not all Active Directory attributes are retrieved successfully - DropDownMap",
			log:             `24458 WARN  External-Active-Directory: Not all Active Directory attributes are retrieved successfully, ConfigVersionID=84, UserName=test, AuthenticationMethod=PAP_ASCII, CurrentIDStoreName=TEST, ExternalGroups=S-1-5-21-2415333095-1493383835-2404072637-142704, ExternalGroups=S-1-5-21-2415333095-1445987455-2404072637-303892, ExternalGroups=S-0-0-00-9995123095-1493383835-2404972636-000000, ExternalGroups=S-1-0-00-2419999995-1000003835-2404072999-000, IdentityAccessRestricted=false, Response={QueryResult=Passed; }`,
			expectedMarshal: []byte(`{"AuthenticationMethod":"PAP_ASCII","ConfigVersionID":"84","CurrentIDStoreName":"TEST","EventDescription":"Not all Active Directory attributes are retrieved successfully","EventType":0,"ExternalGroups":["S-1-5-21-2415333095-1493383835-2404072637-142704","S-1-5-21-2415333095-1445987455-2404072637-303892","S-0-0-00-9995123095-1493383835-2404972636-000000","S-1-0-00-2419999995-1000003835-2404072999-000"],"IdentityAccessRestricted":"false","Response":{"QueryResult":"Passed","MessageDetails":{"UnexpectedFields":{}}},"UserName":"test","MessageDetails":{"UnexpectedFields":{}}}`),
			expectedError:   nil,
		},
		{
			name:            "Endpoint failed authentication of the same scenario several times and was rejected - DropDownMap",
			log:             `5449 NOTICE RADIUS: Endpoint failed authentication of the same scenario several times and was rejected, ConfigVersionID=84, Device IP Address=10.20.30.40, Device Port=8888, DestinationIPAddress=10.20.100.100, DestinationPort=6666, RadiusPacketType=AccessRequest, Protocol=Radius, NetworkDeviceName=TEST, User-Name=INVALID, NAS-IP-Address=10.30.50.50, NAS-Port=10000, Service-Type=Framed, Framed-MTU=1500, State=37CPMSessionID=000000000000MMMM97CJJJJC\;42SessionID=TEST/102123456/7894561\;, Called-Station-ID=AA-AA-AA-AA-AA-AA, Calling-Station-ID=BB-BB-BB-BB-BB-BB, NAS-Port-Type=Ethernet, NAS-Port-Id=GigabitEthernet3/0/5, EAP-Key-Name=, cisco-av-pair=service-type=Framed, cisco-av-pair=audit-session-id=000000000000AZERTYUIOPQS, cisco-av-pair=method=dot1x, NetworkDeviceProfileName=Cisco, NetworkDeviceProfileID=87zertyf-0000-0000-0000-212457845454, IsThirdPartyDeviceFlow=false, RadiusFlowType=Wired802_1x, SSID=AA-AA-AA-AA-AA-AA, UserName=INVALID, AcsSessionID=TEST/123456789/1234567, AuthenticationIdentityStore=, AuthenticationMethod=MSCHAPV2, SelectedAccessService=TEST, DetailedInfo=Invalid username or password specified\, Retry is  allowed, UseCase=Eap Chaining, FailureReason=22056 Subject not found in the applicable identity store(s), Step=11001, Step=11017, Step=15049, Step=15008, Step=15048, Step=15048, Step=15048, Step=11507, Step=12500, Step=12625, Step=11006, Step=11001, Step=11018, Step=12101, Step=12100, Step=12625, Step=11006, Step=11001, Step=11018, Step=12102, Step=12800, Step=12805, Step=12806, Step=12807, Step=12808, Step=12809, Step=12105, Step=11006, Step=11001, Step=11018, Step=12104, Step=12105, Step=11006, Step=11001, Step=11018, Step=12104, Step=12105, Step=11006, Step=11001, Step=11018, Step=12104, Step=12105, Step=11006, Step=11001, Step=11018, Step=12104,805, Step=12105, Step=11006, Step=11001, Step=11018, Step=12104, Step=12811, Step=12812, Step=12813, Step=12804, Step=12801, Step=12802, Step=12816, Step=12207, Step=12226, Step=12105, Step=11006, Step=11001, Step=11018, Step=12104, Step=12805, Step=12806, Step=12807, Step=12808, Step=12809, Step=12105, Step=11006, Step=11001, Step=11018, Step=12104, Step=12105, Step=11006, Step=11001, Step=11018, Step=12104, Step=12105, Step=11006, Step=11001, Step=11018, Step=12104, Step=12105, Step=11006, Step=11001, Step=11018, Step=12104, Step=12105, Step=11006, Step=11001, Step=11018, Step=12104, Step=12105, Step=11006, Step=11001, Step=11018, Step=12104, Step=12811, Step=12812, Step=12813, Step=12804, Step=12801, Step=12802, Step=12226, Step=12205, Step=12149, Step=12105, Step=11006, Step=11001, Step=11018, Step=12104, Step=12209, Step=12218, Step=12125, Step=11521, Step=12105, Step=11006, Step=11001, Step=11018, Step=12104, Step=12213, Step=12215, Step=11522, Step=11806, Step=12105, Step=11006, Step=11001, Step=11018, Step=12104, Step=11808, Step=15041, Step=15048, Step=15048, Step=15048, Step=22072, Step=15013, Step=24431, Step=24325, Step=24313, Step=24318, Step=24367, Step=24367, Step=24367, Step=24367, Step=24322, Step=24352, Step=24437, Step=15013, Step=24431, Step=24325, Step=24313, Step=24318, Step=24322, Step=24352, Step=24437, Step=22016, Step=22056, Step=22058, Step=22061, Step=11823, Step=12105, Step=11006, Step=11001, Step=11018, Step=12104, Step=11810, Step=11815, Step=11520, Step=12117, Step=22028, Step=12967, Step=12105, Step=11006, Step=11001, Step=11018, Step=12104, Step=12218, Step=12125, Step=11521, Step=12105, Step=11006, Step=11001, Step=11018, Step=12104, Step=12213, Step=12216, Step=12967, Step=12105, Step=11006, Step=11001, Step=11018, Step=12104, Step=61025, Step=12109, Step=11504, Step=11003, Step=5449, SelectedAuthenticationIdentityStores=TEST, SelectedAuthenticationIdentityStores=TEST, NetworkDeviceGroups=Location#All Locations#Velizy, NetworkDeviceGroups=Device Type#All Device Types#Switches, NetworkDeviceGroups=IPSEC#Is IPSEC Device#No, IdentityPolicyMatchedRule=TEST, EapTunnel=EAP-FAST, EapAuthentication=EAP-MSCHAPv2, CPMSessionID=000000000000A94297CCA0EC, EndPointMACAddress=DD-DD-DD-DD-DD-DD, EapChainingResult=User and machine both failed, ISEPolicySetName=LAN - DOT1X, IdentitySelectionMatchedRule=TEST, AD-Error-Details=Domain trust is one-way, StepData=4= DEVICE.Device Type, StepData=5= DEVICE.Location, StepData=6= Normalised Radius.RadiusFlowType, StepData=134= Network Access.UserName, StepData=135= Network Access.EapTunnel, StepData=136= Network Access.AuthenticationMethod, StepData=137=Chaining_AD_Media_PKI, StepData=138=TEST, StepData=139=TEST, StepData=140=INVALID, StepData=141=test, StepData=142=test, StepData=143=Groupe-test.com\,INVALID, StepData=144=test.com\,INVALID, StepData=145=test.com\,INVALID, StepData=146=test.com\,INVALID, StepData=148=ERROR_NO_SUCH_USER, StepData=149=TEST, StepData=150=TEST, StepData=151=TEST, StepData=152=INVALID, StepData=153=test, StepData=154=test, StepData=156=ERROR_NO_SUCH_USER, StepData=157=TEST, IsMachineIdentity=false, TLSCipher=ECDHE-RSA-AES256-SHA, TLSVersion=TLSv1, DTLSSupport=Unknown, Network Device Profile=Cisco, Location=Location#All Locations#TEST, Device Type=Device Type#All Device Types#Switches, IPSEC=IPSEC#Is IPSEC Device#No, Response={RadiusPacketType=AccessReject; }`,
			expectedMarshal: []byte(`{"ADErrorDetails":"Domain trust is one-way","AcsSessionID":"TEST/123456789/1234567","AuthenticationIdentityStore":"","AuthenticationMethod":"MSCHAPV2","CPMSessionID":"000000000000A94297CCA0EC","CalledStationID":["AA-AA-AA-AA-AA-AA"],"CallingStationID":["BB-BB-BB-BB-BB-BB"],"CiscoAVPair":{"AuditSessionID":"000000000000AZERTYUIOPQS","Method":"dot1x","ServiceType":"Framed"},"ConfigVersionID":"84","DTLSSupport":"Unknown","DestinationIPAddress":"10.20.100.100","DestinationPort":"6666","DetailedInfo":"Invalid username or password specified, Retry is  allowed","DeviceIPAddress":"10.20.30.40","DevicePort":"8888","DeviceType":{"Value":"All Device Types","Child":{"Value":"Switches"}},"EapAuthentication":"EAP-MSCHAPv2","EapTunnel":"EAP-FAST","EAPKeyName":"","EapChainingResult":"User and machine both failed","EndPointMACAddress":"DD-DD-DD-DD-DD-DD","EventDescription":"Endpoint failed authentication of the same scenario several times and was rejected","EventType":0,"FailureReason":"22056 Subject not found in the applicable identity store(s)","FramedMTU":"1500","IPSEC":{"Value":"Is IPSEC Device","Child":{"Value":"No"}},"ISEPolicySetName":"LAN - DOT1X","IdentityPolicyMatchedRule":"TEST","IdentitySelectionMatchedRule":"TEST","IsMachineIdentity":false,"IsThirdPartyDeviceFlow":false,"Location":{"Value":"All Locations","Child":{"Value":"TEST"}},"NASIPAddress":"10.30.50.50","NASPort":"10000","NASPortID":"GigabitEthernet3/0/5","NASPortType":"Ethernet","NetworkDeviceProfile":"Cisco","NetworkDeviceGroups":{"Device Type":{"Value":"All Device Types","Child":{"Value":"Switches"}},"IPSEC":{"Value":"Is IPSEC Device","Child":{"Value":"No"}},"Location":{"Value":"All Locations","Child":{"Value":"Velizy"}}},"NetworkDeviceName":"TEST","NetworkDeviceProfileID":"87zertyf-0000-0000-0000-212457845454","NetworkDeviceProfileName":"Cisco","Protocol":"Radius","RadiusFlowType":"Wired802_1x","RadiusPacketType":"AccessRequest","Response":{"RadiusPacketType":"AccessReject","MessageDetails":{"UnexpectedFields":{}}},"SSID":"AA-AA-AA-AA-AA-AA","SelectedAccessService":"TEST","SelectedAuthenticationIdentityStores":"TEST","ServiceType":"Framed","State":["37CPMSessionID=000000000000MMMM97CJJJJC;42SessionID=TEST/102123456/7894561;"],"Step":["11001","11017","15049","15008","15048","15048","15048","11507","12500","12625","11006","11001","11018","12101","12100","12625","11006","11001","11018","12102","12800","12805","12806","12807","12808","12809","12105","11006","11001","11018","12104","12105","11006","11001","11018","12104","12105","11006","11001","11018","12104","12105","11006","11001","11018","12104,805","12105","11006","11001","11018","12104","12811","12812","12813","12804","12801","12802","12816","12207","12226","12105","11006","11001","11018","12104","12805","12806","12807","12808","12809","12105","11006","11001","11018","12104","12105","11006","11001","11018","12104","12105","11006","11001","11018","12104","12105","11006","11001","11018","12104","12105","11006","11001","11018","12104","12105","11006","11001","11018","12104","12811","12812","12813","12804","12801","12802","12226","12205","12149","12105","11006","11001","11018","12104","12209","12218","12125","11521","12105","11006","11001","11018","12104","12213","12215","11522","11806","12105","11006","11001","11018","12104","11808","15041","15048","15048","15048","22072","15013","24431","24325","24313","24318","24367","24367","24367","24367","24322","24352","24437","15013","24431","24325","24313","24318","24322","24352","24437","22016","22056","22058","22061","11823","12105","11006","11001","11018","12104","11810","11815","11520","12117","22028","12967","12105","11006","11001","11018","12104","12218","12125","11521","12105","11006","11001","11018","12104","12213","12216","12967","12105","11006","11001","11018","12104","61025","12109","11504","11003","5449"],"StepData":"157=TEST","TLSCipher":"ECDHE-RSA-AES256-SHA","TLSVersion":"TLSv1","UseCase":"Eap Chaining","UserName":"INVALID","MessageDetails":{"UnexpectedFields":{}}}`),
			expectedError:   nil,
		},
		{
			name:            "Successful parse of Response",
			log:             `5200 NOTICE Passed-Authentication: Authentication succeeded, Response={UserName=abcd; User-Name=abcd; Class=CACS:00000000000030982403902:abc-isepsn01/432961906/5707271; Session-Timeout=28800; Termination-Action=RADIUS-Request; Tunnel-Type=(tag=1) VLAN; Tunnel-Medium-Type=(tag=1) 802; Tunnel-Private-Group-ID=(tag=1) 506; cisco-av-pair=profile-name=Xerox-DocuCentre-Printer; LicenseTypes=1; },#015`,
			expectedMarshal: []byte(`{"EventDescription":"Authentication succeeded","EventType":5200,"Response":{"CiscoAVPair":{"ProfileName":"Xerox-DocuCentre-Printer"},"Class":["CACS:00000000000030982403902:abc-isepsn01/432961906/5707271"],"LicenseTypes":"1","SessionTimeout":"28800","TerminationAction":"RADIUS-Request","TunnelMediumType":"(tag=1)802","TunnelPrivateGroupID":"(tag=1)506","TunnelType":"(tag=1)VLAN","UserName":"abcd","MessageDetails":{"UnexpectedFields":{}}},"MessageDetails":{"UnexpectedFields":{}}}`),
			expectedError:   nil,
		},
		{
			name:            "Response object has unexpected field",
			log:             `5200 NOTICE Passed-Authentication: Authentication succeeded, Response={SomeUnexpectedField=SomeValue;}`,
			expectedMarshal: []byte(`{"EventDescription":"Authentication succeeded","EventType":5200,"Response":{"MessageDetails":{"UnexpectedFields":{"SomeUnexpectedField":"SomeValue"}}},"MessageDetails":{"UnexpectedFields":{}}}`),
			expectedError:   nil,
		},
		{
			name:            "Response object gives parse failure",
			log:             `5200 NOTICE Passed-Authentication: Authentication succeeded, Response={IsEndpointInRejectMode=1234}`,
			expectedMarshal: []byte(`{"EventDescription":"Authentication succeeded","EventType":5200,"MessageDetails":{"UnexpectedFields":{}}}`),
			expectedError:   &ParseError{},
		},
		{
			name:            "Response object is empty",
			log:             `5200 NOTICE Passed-Authentication: Authentication succeeded, Response={}`,
			expectedMarshal: []byte(`{"EventDescription":"Authentication succeeded","EventType":5200,"MessageDetails":{"UnexpectedFields":{}}}`),
			expectedError:   nil,
		},
		{
			name:            "Response field is empty",
			log:             `5200 NOTICE Passed-Authentication: Authentication succeeded, Response=`,
			expectedMarshal: []byte(`{"EventDescription":"Authentication succeeded","EventType":5200,"MessageDetails":{"UnexpectedFields":{}}}`),
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
