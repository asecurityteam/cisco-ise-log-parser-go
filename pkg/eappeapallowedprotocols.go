package parser

import "time"

type EAPPEAPAllowedProtocolsLog struct {
	AccessService            string     `json:"access_service,omitempty"`
	AccountingAuthentication string     `json:"accounting_authentication,omitempty"`
	AccountingSessionID      string     `json:"accounting_session_id,omitempty"`
	AccountingStatusType     string     `json:"accounting_status_type,omitempty"`
	AcsSessionID             string     `json:"acs_session_id,omitempty"`
	Aggregator               string     `json:"aggregator,omitempty"`
	AuditSessionID           string     `json:"audit_session_id,omitempty"`
	BusinessUnit             string     `json:"business_unit,omitempty"`
	CalledStationID          string     `json:"called_station_id,omitempty"`
	Dest                     string     `json:"dest,omitempty"`
	DeviceType               string     `json:"device_type,omitempty"`
	Duration                 string     `json:"duration,omitempty"`
	Env                      string     `json:"env,omitempty"`
	EventType                string     `json:"eventtype,omitempty"`
	Host                     string     `json:"host,omitempty"`
	Hostname                 string     `json:"hostname,omitempty"`
	Location                 string     `json:"location,omitempty"`
	Logtype                  string     `json:"logtype,omitempty"`
	Message                  LogMessage `json:"message,omitempty"`
	Mnemonic                 string     `json:"mnemonic,omitempty"`
	NasIdentifier            string     `json:"nas_identifier,omitempty"`
	NasIPAddress             string     `json:"nas_ip_address,omitempty"`
	NasPort                  string     `json:"nas_port,omitempty"`
	NasPortType              string     `json:"nas_port_type,omitempty"`
	NetworkDeviceName        string     `json:"network_device_name,omitempty"`
	NetworkDeviceProfile     string     `json:"network_device_profile,omitempty"`
	Notice                   string     `json:"notice,omitempty"`
	ServiceType              string     `json:"service_type,omitempty"`
	Signature                string     `json:"signature,omitempty"`
	Src                      string     `json:"src,omitempty"`
	Time                     time.Time  `json:"time,omitempty"`
	TunnelMediumType         string     `json:"tunnel_medium_type,omitempty"`
	TunnelPrivateGroupID     string     `json:"tunnel_private_group_id,omitempty"`
	TunnelType               string     `json:"tunnel_type,omitempty"`
	User                     string     `json:"user,omitempty"`
	WlanID                   string     `json:"wlan_id,omitempty"`
}

type EAPPEAPAllowedProtocolsLogMessage struct {
	ADUserCandidateIdentities            string
	ADUserDNSDomain                      string
	ADUserJoinPoint                      string
	ADUserNetBiosName                    string
	ADUserQualifiedName                  string
	ADUserResolvedDNs                    string
	ADUserResolvedIdentities             string
	ADUserSamAccountName                 string
	AKI                                  string
	AcctAuthentic                        string
	AcctDelayTime                        string
	AcctInputGigawords                   string
	AcctInputOctets                      string
	AcctInputPackets                     string
	AcctOutputGigawords                  string
	AcctOutputOctets                     string
	AcctOutputPackets                    string
	AcctSessionId                        string
	AcctSessionTime                      string
	AcctStatusType                       string
	AcctTerminateCause                   string
	AcsSessionID                         string
	AirespaceWlanId                      string
	AllowEasyWiredSession                string
	AuthenticationIdentityStore          string
	AuthenticationMethod                 string
	AuthenticationStatus                 string
	AuthorizationPolicyMatchedRule       string
	CPMSessionID                         string
	CalledStationID                      string
	CallingStationID                     string
	ChargeableUserIdentity               string
	CiscoAvPair                          []string
	Class                                []string
	Company                              string
	ConfigVersionId                      string
	DTLSSupport                          string
	DaysToExpiry                         string
	Department                           string
	DestinationIPAddress                 string
	DestinationPort                      string
	DetailedInfo                         string
	DeviceIPAddress                      string
	DeviceType                           string
	DistinguishedName                    string
	EapAuthentication                    string
	EapTunnel                            string
	EmployeeID                           string
	EndPointMACAddress                   string
	EndPointMatchedProfile               string
	EventTimestamp                       string
	ExtendedKeyUsageName                 []string
	ExtendedKeyUsageOID                  []string
	FailureReason                        string
	FramedIPAddress                      string
	FramedMTU                            string
	HostIdentityGroup                    string
	IPSEC                                string
	ISEPolicySetName                     string
	IdentityGroup                        string
	IdentityPolicyMatchedRule            string
	IdentitySelectionMatchedRule         string
	IsMachineAuthentication              string
	IsMachineIdentity                    string
	IsThirdPartyDeviceFlow               string
	Issuer                               string
	IssuerCommonName                     string
	IssuerDomainComponent                []string
	KeyUsage                             []int
	L                                    string
	Location                             string
	LocationCapable                      string
	NASIPAddress                         string
	NASIdentifier                        string
	NASPort                              string
	NASPortId                            string
	NASPortType                          string
	Name                                 string
	NetworkDeviceGroups                  map[string]map[string]string
	NetworkDeviceName                    string
	NetworkDeviceProfile                 string
	NetworkDeviceProfileId               string
	NetworkDeviceProfileName             string
	PostureAssessmentStatus              string
	Protocol                             string
	RadiusFlowType                       string
	RequestLatency                       string
	Response                             string
	Role                                 string
	SAMAccountName                       string
	SSID                                 string
	Security                             string
	SelectedAccessService                string
	SelectedAuthenticationIdentityStores string
	SelectedAuthorizationProfiles        string
	SerialNumber                         string
	ServiceType                          string
	State                                []string
	Step                                 []int
	StepData                             map[string]string
	StepLatency                          string
	Subject                              string
	SubjectAlternativeName               string
	SubjectAlternativeNameEmail          string
	SubjectAlternativeNameOtheName       string
	SubjectCommonName                    string
	TLSCipher                            string
	TLSVersion                           string
	Team                                 string
	TemplateName                         string
	TextEncodedORAddress                 string
	TunnelMediumType                     string
	TunnelPrivateGroupID                 string
	TunnelType                           string
	UserAccountControl                   string
	UserName                             string
}
