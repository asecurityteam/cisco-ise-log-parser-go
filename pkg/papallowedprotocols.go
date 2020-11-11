package parser

import "time"

type PAPAllowedProtocolsLog struct {
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
	User                     string     `json:"user,omitempty"`
}

type PAPAllowedProtocolsLogMessage struct {
	ADErrorDetails                       string
	ADUserCandidateIdentities            string
	ADUserDNSDomain                      string
	ADUserJoinPoint                      string
	ADUserNetBiosName                    string
	ADUserQualifiedName                  string
	ADUserResolvedDNs                    string
	ADUserResolvedIdentities             string
	ADUserSamAccountName                 string
	AcctAuthentic                        string
	AcctDelayTime                        string
	AcctInputOctets                      string
	AcctInputPackets                     string
	AcctOutputOctets                     string
	AcctOutputPackets                    string
	AcctSessionId                        string
	AcctSessionTime                      string
	AcctStatusType                       string
	AcctTerminateCause                   string
	AcsSessionID                         string
	AirespaceWlanId                      string
	AuthenticationIdentityStore          string
	AuthenticationMethod                 string
	AuthenticationStatus                 string
	AuthorizationPolicyMatchedRule       string
	CPMSessionID                         string
	CVPN3000ASAPIX7xClientType           string
	CVPN3000ASAPIX7xSessionSubtype       string
	CVPN3000ASAPIX7xSessionType          string
	CVPN3000ASAPIX7xTunnelGroupName      string
	CalledStationID                      string
	CallingStationID                     string
	ChargeableUserIdentity               string
	Class                                []string
	ConfigVersionId                      string
	DC                                   []string
	DTLSSupport                          string
	DestinationIPAddress                 string
	DestinationPort                      string
	DeviceIPAddress                      string
	DeviceType                           string
	EapAuthentication                    string
	EapTunnel                            string
	EndPointMACAddress                   string
	EndPointMatchedProfile               string
	FramedIPAddress                      string
	FramedMTU                            string
	FramedProtocol                       string
	HostIdentityGroup                    string
	IPSEC                                string
	ISEPolicySetName                     string
	IdentityAccessRestricted             string
	IdentityGroup                        string
	IdentityPolicyMatchedRule            string
	IdentitySelectionMatchedRule         string
	IsMachineAuthentication              string
	IsThirdPartyDeviceFlow               string
	Location                             string
	LocationCapable                      string
	ModelName                            string
	NASIPAddress                         string
	NASIdentifier                        string
	NASPort                              string
	NASPortId                            string
	NASPortType                          string
	Name                                 string
	NetworkDeviceProfile                 string
	NetworkDeviceGroups                  map[string]map[string]string
	NetworkDeviceName                    string
	NetworkDeviceProfileId               string
	NetworkDeviceProfileName             string
	OU                                   string
	PostureAssessmentStatus              string
	Protocol                             string
	RadiusFlowType                       string
	RequestLatency                       string
	Role                                 string
	SSID                                 string
	Security                             string
	SelectedAccessService                string
	SelectedAuthenticationIdentityStores string
	SelectedAuthorizationProfiles        string
	ServiceType                          string
	SoftwareVersion                      string
	State                                []string
	Step                                 []int
	StepData                             map[string]string
	TLSCipher                            string
	TLSVersion                           string
	Team                                 string
	TunnelClientEndpoint                 string
	TunnelMediumType                     string
	TunnelPrivateGroupID                 string
	TunnelType                           string
	Type                                 string
	UserName                             string
}
