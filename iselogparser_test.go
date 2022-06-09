package ciscoiselogparser

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParsePapAllowedProtocol(t *testing.T) {
	papAllowedProtocolLogEvent := json.RawMessage(`{"dest":"10.11.22.33","dest_ip":"172.11.22.33","dest_port":"1812","duration":"29","user":"catlas","nas_ip_address":"10.11.22.33","nas_port":"207360000","called_station_id":"104.111.222.333","src":"76.11.22.33","nas_port_type":"Virtual","audit_session_id":"0a1b2c3d4e5f","acs_session_id":"sc1-isepsn01/987654321/1234567","network_device_name":"vpn01-sc1","access_service":"PAP-ALLOWED-PROTOCOLS","auth_id_store":"office.company.com","auth_method":"PAP_ASCII","authz_profile":"VPN-StaffManaged-Policy","user_category":"Endpoint Identity Groups:Profiled:Workstation","identify_policy_rule":"Default","authz_policy_rule":"VPN-Staff-Managed","employee_id":"123","response":"{Class=StaffManagedPolicy; Class=CACS:0a1b2c3d4e5f:sc1-isepsn01/987654321/1234567; cisco-av-pair=profile-name=Workstation; LicenseTypes=1; ","protocol":"Radius","network_device_profile":"Cisco","ssid":"104.111.222.333","selected_auth_id_store":"office.company.com","authc_status":"AuthenticationPassed","posture_assessment":"NotApplicable","endpoint_profile":"Workstation","ise_policy_set":"VPN","selection_rule_match":"Default","ad_resolved_id":"catlas@office.company.com","ad_candidate_id":"catlas@office.company.com","ad_user_join_point":"OFFICE.COMPANY.COM","radius_step_data":"47=office.company.com","ad_user_resolved_dn":"CN=catlas\\","ad_user_dns_domain":"office.company.com","host_identity_group":"Endpoint Identity Groups:Profiled:Workstation","location":"Location#All Locations#SC#SC1","device_type":"Device Type#All Device Types#Cisco#Firewall","notice":"Passed-Authentication: Authentication succeeded","signature":"Passed_Authentications","mnemonic":"",
			"message":"5200 NOTICE Passed-Authentication: Authentication succeeded, ConfigVersionId=113, Device IP Address=10.11.22.33, DestinationIPAddress=172.11.22.33, DestinationPort=1812, UserName=catlas, Protocol=Radius, RequestLatency=29, NetworkDeviceName=vpn01-sc1, User-Name=catlas, NAS-IP-Address=10.11.22.33, NAS-Port=207360000, Called-Station-ID=104.111.222.333, Calling-Station-ID=76.11.22.33, NAS-Port-Type=Virtual, Tunnel-Client-Endpoint=(tag=0) 76.11.22.33, cisco-av-pair=mdm-tlv=device-platform=win, cisco-av-pair=mdm-tlv=device-mac=a0-b1-c3-d4-e5-f6, cisco-av-pair=mdm-tlv=device-type=Dell Inc. XPS 15 3000, cisco-av-pair=mdm-tlv=device-platform-version=10.0 , cisco-av-pair=mdm-tlv=device-public-mac=a0-b1-c3-d4-e5-f6, cisco-av-pair=mdm-tlv=ac-user-agent=AnyConnect Windows 5.0, cisco-av-pair=mdm-tlv=device-uid=0A1B2C3D4E5F0A1B2C3D4E5F0A1B2C3D4E5F0A1B2C3D4E5F0A1B2C3D4E5F, cisco-av-pair=audit-session-id=0a1b2c3d4e5f, cisco-av-pair=ip:source-ip=76.11.22.33, cisco-av-pair=coa-push=true, CVPN3000/ASA/PIX7x-Tunnel-Group-Name=managed, OriginalUserName=catlas, NetworkDeviceProfileName=Cisco, NetworkDeviceProfileId=a1234567-b111-c222-d333-e0123456abc, IsThirdPartyDeviceFlow=false, SSID=104.111.222.333, CVPN3000/ASA/PIX7x-Client-Type=2, AcsSessionID=sc1-isepsn01/987654321/1234567, AuthenticationIdentityStore=office.company.com, AuthenticationMethod=PAP_ASCII, SelectedAccessService=PAP-ALLOWED-PROTOCOLS, SelectedAuthorizationProfiles=VPN-StaffManaged-Policy, IsMachineAuthentication=false, IdentityGroup=Endpoint Identity Groups:Profiled:Workstation, Step=11001, Step=11017, Step=15049, Step=15008, Step=15048, Step=15048, Step=15041, Step=15013, Step=24430, Step=24325, Step=24313, Step=24319, Step=24323, Step=24343, Step=24402, Step=22037, Step=24715, Step=15036, Step=24209, Step=24211, Step=15048, Step=24432, Step=24325, Step=24313, Step=24319, Step=24323, Step=24355, Step=24416, Step=24355, Step=24420, Step=24100, Step=15048, Step=15048, Step=15048, Step=15048, Step=15016, Step=22081, Step=22080, Step=24432, Step=24325, Step=24313, Step=24319, Step=24323, Step=24355, Step=24416, Step=24355, Step=24420, Step=24100, Step=11002, SelectedAuthenticationIdentityStores=office.company.com, AuthenticationStatus=AuthenticationPassed, NetworkDeviceGroups=Security#Security#High-Security, NetworkDeviceGroups=Location#All Locations#SC#SC1, NetworkDeviceGroups=Device Type#All Device Types#Cisco#Firewall, NetworkDeviceGroups=IPSEC#Is IPSEC Device#No, NetworkDeviceGroups=Team#Team#Core Network and Automation, NetworkDeviceGroups=Role#Role, IdentityPolicyMatchedRule=Default, AuthorizationPolicyMatchedRule=VPN-Staff-Managed, CPMSessionID=0a1b2c3d4e5f, PostureAssessmentStatus=NotApplicable, EndPointMatchedProfile=Workstation, ISEPolicySetName=VPN, IdentitySelectionMatchedRule=Default, AD-User-Resolved-Identities=catlas@office.company.com, AD-User-Candidate-Identities=catlas@office.company.com, AD-User-Join-Point=OFFICE.COMPANY.COM, StepData=4= Normalised Radius.RadiusFlowType (4 times), StepData=5= DEVICE.Device Type, StepData=7=office.company.com, StepData=8=office.company.com, StepData=9=catlas, StepData=10=office.company.com, StepData=11=office.company.com, StepData=13=catlas@office.company.com, StepData=14=office.company.com, StepData=20= Cisco-VPN3000.CVPN3000/ASA/PIX7x-Tunnel-Group-Name, StepData=0=office.company.com, StepData=1=catlas@office.company.com, StepData=2=office.company.com, StepData=3=office.company.com, StepData=5=office.company.com, StepData=6=office.company.com, StepData=7=office.company.com, StepData=8=office.company.com, StepData=9=office.company.com, StepData=31= office.company.com.distinguishedName, StepData=32= office.company.com.ExternalGroups (4 times), StepData=33= DEVICE.Model Name, StepData=34= office.company.com.ExternalGroups, StepData=38=office.company.com, StepData=39=catlas@office.company.com, StepData=40=office.company.com, StepData=41=office.company.com, StepData=43=office.company.com, StepData=44=office.company.com, StepData=45=office.company.com, StepData=46=office.company.com, StepData=47=office.company.com, AD-User-Resolved-DNs=CN=catlas\\,OU=people\\,DC=office\\,DC=company\\,DC=com, AD-User-DNS-Domain=office.company.com, AD-User-NetBios-Name=company, IsMachineIdentity=false, UserAccountControl=512, AD-User-SamAccount-Name=catlas, AD-User-Qualified-Name=catlas@office.company.com, allowEasyWiredSession=false, DTLSSupport=Unknown, HostIdentityGroup=Endpoint Identity Groups:Profiled:Workstation, Security=Security#Security#High-Security, Network Device Profile=Cisco, Location=Location#All Locations#SC#SC1, Device Type=Device Type#All Device Types#Cisco#Firewall, IPSEC=IPSEC#Is IPSEC Device#No, Role=Role#Role, Team=Team#Team#Core Network and Automation, IdentityAccessRestricted=false, l=Home Office: US\\, United States, employeeID=123, department=My Department, company=Company, sAMAccountName=catlas, distinguishedName=CN=catlas\\,OU=people\\,DC=office\\,DC=company\\,DC=com, Response={Class=StaffManagedPolicy; Class=CACS:0a1b2c3d4e5f:sc1-isepsn01/987654321/1234567; cisco-av-pair=profile-name=Workstation; LicenseTypes=1; },#015","env":"prod","logtype":"cisco_ise","business_unit":"My Business Unit","aggregator":"11.22.33.44","hostname":"ip-10-111-222-333","time":"2020-11-04T16:33:54+00:00"}`)

	var parsedLog IseLogAccessService
	err := json.Unmarshal(papAllowedProtocolLogEvent, &parsedLog)
	assert.NoError(t, err)

	var papAllowedParsed PAPAllowedProtocolsLog
	byteEventLog, err := json.Marshal(parsedLog.EventLog)
	assert.NoError(t, err)
	err = json.Unmarshal(byteEventLog, &papAllowedParsed)
	assert.NoError(t, err)
	assert.Equal(t, "PAP-ALLOWED-PROTOCOLS", papAllowedParsed.AccessService)
	assert.Equal(t, "catlas", papAllowedParsed.User)
	assert.Equal(t, "5200 NOTICE Passed-Authentication", papAllowedParsed.Message.EventType.String())
	assert.Equal(t, "catlas", *papAllowedParsed.Message.ADUserSamAccountName)
	assert.Equal(t, "win", *papAllowedParsed.Message.CiscoAVPair.MDMTLV.DevicePlatform)
}

func TestParseHostAllowedProtocol(t *testing.T) {
	papAllowedProtocolLogEvent := json.RawMessage(`{"dest":"172.11.22.33","dest_ip":"172.10.20.30","dest_port":"1812","duration":"6","user":"0A-1B-2C-3D-4E-5F; Class=CACS:12345678901234567890:atx-isepsn01/987654321/1234567; Session-Timeout=28800; Termination-Action=RADIUS-Request; Tunnel-Type=(tag=1) VLAN; Tunnel-Medium-Type=(tag=1) 802; Tunnel-Private-Group-ID=(tag=1) 663; cisco-av-pair=profile-name=Unknown; LicenseTypes=1; }","nas_ip_address":"172.11.22.33","nas_port":"13","service_type":"Call Check","called_station_id":"70-80-90-10-20-30:my-wifi-network","src":"0A-1B-2C-3D-4E-5F","accounting_session_id":"1a2b3c4d/00:a1:b2:c3:d4:f5/12345678","nas_port_type":"Wireless - IEEE 802.11","audit_session_id":"12345678901234567890","acs_session_id":"atx-isepsn01/987654321/1234567","network_device_name":"my-network-device","nas_identifier":"my-network-device","framed_mtu":"1300","tunnel_type":"(tag=1) VLAN; Tunnel-Medium-Type=(tag=1) 802; Tunnel-Private-Group-ID=(tag=1) 663; cisco-av-pair=profile-name=Unknown; LicenseTypes=1; }","tunnel_medium_type":"(tag=1) 802; Tunnel-Private-Group-ID=(tag=1) 663; cisco-av-pair=profile-name=Unknown; LicenseTypes=1; }","tunnel_private_group_id":"(tag=1) 663; cisco-av-pair=profile-name=Unknown; LicenseTypes=1; }","wlan_id":"7","access_service":"HOST-LOOKUP-ALLOWED-PROTOCOLS","auth_id_store":"Internal Endpoints","auth_method":"Lookup","authz_profile":"vlan-663-SHARED-EQUIPMENT","user_category":"Endpoint Identity Groups:access-device:se","identify_policy_rule":"Authentication Rule 1","authz_policy_rule":"MAB SE","response":"{UserName=00:a1:b2:c3:d4:f5; User-Name=0A-1B-2C-3D-4E-5F; Class=CACS:12345678901234567890:atx-isepsn01/987654321/1234567; Session-Timeout=28800; Termination-Action=RADIUS-Request; Tunnel-Type=(tag=1) VLAN; Tunnel-Medium-Type=(tag=1) 802; Tunnel-Private-Group-ID=(tag=1) 663; cisco-av-pair=profile-name=Unknown; LicenseTypes=1; ","protocol":"Radius","network_device_profile":"Cisco","radius_flow_type":"WirelessMAB","ssid":"70-80-90-10-20-30:my-wifi-network","selected_auth_id_store":"Internal Endpoints","authc_status":"AuthenticationPassed","endpoint_mac_address":"0A-1B-2C-3D-4E-5F","posture_assessment":"NotApplicable","endpoint_profile":"Unknown","ise_policy_set":"MAB","selection_rule_match":"Authentication Rule 1","radius_step_data":"6=Internal Endpoints","host_identity_group":"Endpoint Identity Groups:access-device:se","location":"Location#All Locations#World#US","device_type":"Device Type#All Device Types#Cisco#WLC","notice":"Passed-Authentication: Authentication succeeded","signature":"Passed_Authentications","mnemonic":"",
			"message":"5200 NOTICE Passed-Authentication: Authentication succeeded, ConfigVersionId=21, Device IP Address=172.11.22.33, DestinationIPAddress=172.10.20.30, DestinationPort=1812, UserName=0A-1B-2C-3D-4E-5F, Protocol=Radius, RequestLatency=6, NetworkDeviceName=my-network-device, User-Name=12345678abc, NAS-IP-Address=172.11.22.33, NAS-Port=13, Service-Type=Call Check, Framed-MTU=1300, Called-Station-ID=70-80-90-10-20-30:my-wifi-network, Calling-Station-ID=0A-1B-2C-3D-4E-5F, NAS-Identifier=my-network-device, Acct-Session-Id=1a2b3c4d/00:a1:b2:c3:d4:f5/12345678, NAS-Port-Type=Wireless - IEEE 802.11, Tunnel-Type=(tag=0) VLAN, Tunnel-Medium-Type=(tag=0) 802, Tunnel-Private-Group-ID=(tag=0) 665, cisco-av-pair=audit-session-id=12345678901234567890, Airespace-Wlan-Id=7, OriginalUserName=12345678abc, NetworkDeviceProfileName=Cisco, NetworkDeviceProfileId=a1234567-b111-c222-d333-e0123456abc, IsThirdPartyDeviceFlow=false, RadiusFlowType=WirelessMAB, SSID=70-80-90-10-20-30:my-wifi-network, AcsSessionID=atx-isepsn01/987654321/1234567, AuthenticationIdentityStore=Internal Endpoints, AuthenticationMethod=Lookup, SelectedAccessService=HOST-LOOKUP-ALLOWED-PROTOCOLS, SelectedAuthorizationProfiles=vlan-663-SHARED-EQUIPMENT, UseCase=Host Lookup, IdentityGroup=Endpoint Identity Groups:access-device:se, Step=11001, Step=11017, Step=11027, Step=15049, Step=15008, Step=15041, Step=15013, Step=24209, Step=24211, Step=22037, Step=24715, Step=15036, Step=15016, Step=24209, Step=24211, Step=11002, SelectedAuthenticationIdentityStores=Internal Endpoints, AuthenticationStatus=AuthenticationPassed, NetworkDeviceGroups=Location#All Locations#World#US, NetworkDeviceGroups=Device Type#All Device Types#Cisco#WLC, NetworkDeviceGroups=IPSEC#Is IPSEC Device#No, NetworkDeviceGroups=Security#Security, NetworkDeviceGroups=Role#Role, NetworkDeviceGroups=Team#Team, IdentityPolicyMatchedRule=Authentication Rule 1, AuthorizationPolicyMatchedRule=MAB SE, UserType=Host, CPMSessionID=12345678901234567890, EndPointMACAddress=0A-1B-2C-3D-4E-5F, PostureAssessmentStatus=NotApplicable, EndPointMatchedProfile=Unknown, DeviceRegistrationStatus=notRegistered, ISEPolicySetName=MAB, IdentitySelectionMatchedRule=Authentication Rule 1, StepData=6=Internal Endpoints, allowEasyWiredSession=false, DTLSSupport=Unknown, HostIdentityGroup=Endpoint Identity Groups:access-device:se, Security=Security#Security, Network Device Profile=Cisco, Location=Location#All Locations#World#US, Device Type=Device Type#All Device Types#Cisco#WLC, IPSEC=IPSEC#Is IPSEC Device#No, Role=Role#Role, Team=Team#Team, Name=Endpoint Identity Groups:access-device:se, Response={UserName=00:a1:b2:c3:d4:f5; User-Name=0A-1B-2C-3D-4E-5F; Class=CACS:12345678901234567890:atx-isepsn01/987654321/1234567; Session-Timeout=28800; Termination-Action=RADIUS-Request; Tunnel-Type=(tag=1) VLAN; Tunnel-Medium-Type=(tag=1) 802; Tunnel-Private-Group-ID=(tag=1) 663; cisco-av-pair=profile-name=Unknown; LicenseTypes=1; },#015","env":"prod","logtype":"cisco_ise","business_unit":"My Business Unit","aggregator":"11.22.33.44","hostname":"ip-10-111-222-333","time":"2020-11-06T22:54:14+00:00"}`)

	var parsedLog IseLogAccessService
	err := json.Unmarshal(papAllowedProtocolLogEvent, &parsedLog)
	assert.NoError(t, err)

	var hostLookupParsed HostLookupAllowedProtocolsLog
	byteEventLog, err := json.Marshal(parsedLog.EventLog)
	assert.NoError(t, err)
	err = json.Unmarshal(byteEventLog, &hostLookupParsed)
	assert.NoError(t, err)
	assert.Equal(t, "HOST-LOOKUP-ALLOWED-PROTOCOLS", hostLookupParsed.AccessService)
	assert.Equal(t, "Wireless - IEEE 802.11", hostLookupParsed.NasPortType)
	assert.Equal(t, "5200 NOTICE Passed-Authentication", hostLookupParsed.Message.EventType.String())
	assert.Equal(t, "my-network-device", *hostLookupParsed.Message.NetworkDeviceName)
	assert.Equal(t, "All Locations -> World -> US", hostLookupParsed.Message.Location.String())
}

func TestParseEapPeapAllowedProtocol(t *testing.T) {
	papAllowedProtocolLogEvent := json.RawMessage(`{"dest":"10.11.22.33","duration":"5","nas_ip_address":"10.11.22.33","nas_port":"50131","service_type":"Framed","accounting_status_type":"Start","accounting_session_id":"00001111","accounting_authentication":"Local","nas_port_type":"Ethernet","acs_session_id":"mnl-isepsn01/987654321/1234567","network_device_name":"0000-00-switch01","access_service":"EAP-PEAP-ALLOWED-PROTOCOLS","network_device_profile":"Cisco","location":"Location#All Locations#World#USA","device_type":"Device Type#All Device Types#Cisco#Switch","notice":"Radius-Accounting: RADIUS Accounting start request","signature":"RADIUS_Accounting","mnemonic":"",
			"message":"3000 NOTICE Radius-Accounting: RADIUS Accounting start request, ConfigVersionId=207, Device IP Address=10.11.22.33, RequestLatency=5, NetworkDeviceName=0000-00-switch01, NAS-IP-Address=10.11.22.33, NAS-Port=50131, Service-Type=Framed, Acct-Status-Type=Start, Acct-Delay-Time=0, Acct-Session-Id=00001111, Acct-Authentic=Local, NAS-Port-Type=Ethernet, NAS-Port-Id=GigabitEthernet1/0/31, undefined-151=1A2B3C4D, cisco-av-pair=connect-progress=Call Up, AcsSessionID=mnl-isepsn01/987654321/1234567, SelectedAccessService=EAP-PEAP-ALLOWED-PROTOCOLS, Step=11004, Step=11017, Step=11117, Step=15049, Step=15008, Step=15048, Step=11005, NetworkDeviceGroups=Location#All Locations#World#USA, NetworkDeviceGroups=Device Type#All Device Types#Cisco#Switch, NetworkDeviceGroups=IPSEC#Is IPSEC Device#No, NetworkDeviceGroups=Security#Security, NetworkDeviceGroups=Role#Role, NetworkDeviceGroups=Team#Team, CPMSessionID=abcdef1234567890abcdef1234567890/12345678901234567, Security=Security#Security, Network Device Profile=Cisco, Location=Location#All Locations#World#USA, Device Type=Device Type#All Device Types#Cisco#Switch, IPSEC=IPSEC#Is IPSEC Device#No, Role=Role#Role, Team=Team#Team, #015","env":"prod","logtype":"cisco_ise","business_unit":"Workplace Technology","aggregator":"11.22.33.44","hostname":"ip-10-111-222-333","time":"2020-11-06T23:01:57+00:00"}`)

	var parsedLog IseLogAccessService
	err := json.Unmarshal(papAllowedProtocolLogEvent, &parsedLog)
	assert.NoError(t, err)

	var eapPeapAllowedParsed EAPPEAPAllowedProtocolsLog
	byteEventLog, err := json.Marshal(parsedLog.EventLog)
	assert.NoError(t, err)
	err = json.Unmarshal(byteEventLog, &eapPeapAllowedParsed)
	assert.NoError(t, err)
	assert.Equal(t, "EAP-PEAP-ALLOWED-PROTOCOLS", eapPeapAllowedParsed.AccessService)
	assert.Equal(t, "Ethernet", eapPeapAllowedParsed.NasPortType)
	assert.Equal(t, "3000 NOTICE Radius-Accounting", eapPeapAllowedParsed.Message.EventType.String())
	assert.Equal(t, "0000-00-switch01", *eapPeapAllowedParsed.Message.NetworkDeviceName)
	assert.Equal(t, "All Locations -> World -> USA", eapPeapAllowedParsed.Message.Location.String())
}

func TestUnknownAccessService(t *testing.T) {
	badProtocolLogEvent := json.RawMessage(`{"access_service":"NOT-A-REAL-PROTOCOL","auth_id_store":"office.company.com",some_other_field"}`)

	var parsedLog IseLogAccessService
	err := json.Unmarshal(badProtocolLogEvent, &parsedLog)
	assert.Error(t, err)
}

func TestPAPAllowedLogMessageUnmarshalError(t *testing.T) {
	papAllowedInvalidJSONLogEvent := json.RawMessage(`{"access_service":"PAP-ALLOWED-PROTOCOLS",
		"message":"5200 NOTICE Passed-Authentication: Authentication succeeded, IsMachineAuthentication=notAboolean;}#015", "time":"2020-11-04T16:33:54+00:00"}`)

	var parsedLog IseLogAccessService
	err := json.Unmarshal(papAllowedInvalidJSONLogEvent, &parsedLog)
	assert.Error(t, err)
	assert.IsType(t, &ParseError{}, err)
}

func TestHostLookupLogMessageUnmarshalError(t *testing.T) {
	hostLookupInvalidJSONLogEvent := json.RawMessage(`{"access_service":"HOST-LOOKUP-ALLOWED-PROTOCOLS",
		"message":"5200 NOTICE Passed-Authentication: Authentication succeeded, IsMachineAuthentication=notAboolean;}#015", "time":"2020-11-04T16:33:54+00:00"}`)

	var parsedLog IseLogAccessService
	err := json.Unmarshal(hostLookupInvalidJSONLogEvent, &parsedLog)
	assert.Error(t, err)
	assert.IsType(t, &ParseError{}, err)
}

func TestEAPPEAPAllowedLogMessageUnmarshalError(t *testing.T) {
	eapPeapAllowedInvalidJSONLogEvent := json.RawMessage(`{"access_service":"EAP-PEAP-ALLOWED-PROTOCOLS",
		"message":"5200 NOTICE Passed-Authentication: Authentication succeeded, IsMachineAuthentication=notAboolean;}#015", "time":"2020-11-04T16:33:54+00:00"}`)

	var parsedLog IseLogAccessService
	err := json.Unmarshal(eapPeapAllowedInvalidJSONLogEvent, &parsedLog)
	assert.Error(t, err)
	assert.IsType(t, &ParseError{}, err)
}

func TestInvalidISELogJSON(t *testing.T) {
	invalidJSONLogEvent := json.RawMessage(`{"foo":"bar - missing closing curly brace",`)

	var parsedLog IseLogAccessService
	err := json.Unmarshal(invalidJSONLogEvent, &parsedLog)
	assert.Error(t, err)
	assert.IsType(t, &json.SyntaxError{}, err)
}
