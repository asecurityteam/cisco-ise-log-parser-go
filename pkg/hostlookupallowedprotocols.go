package parser

import "time"

type HostLookupAllowedProtocolsLog struct {
	AccessService            string     `json:"access_service,omitempty"`
	AccountingAuthentication string     `json:"accounting_authentication,omitempty"`
	AccountingSessionID      string     `json:"accounting_session_id,omitempty"`
	AccountingStatusType     string     `json:"accounting_status_type,omitempty"`
	AcsSessionID             string     `json:"acs_session_id,omitempty"`
	Aggregator               string     `json:"aggregator,omitempty"`
	AuditSessionID           string     `json:"audit_session_id,omitempty"`
	AuthIDStore              string     `json:"auth_id_store,omitempty"`
	AuthMethod               string     `json:"auth_method,omitempty"`
	AuthcStatus              string     `json:"authc_status,omitempty"`
	AuthzPolicyRule          string     `json:"authz_policy_rule,omitempty"`
	AuthzProfile             string     `json:"authz_profile,omitempty"`
	BusinessUnit             string     `json:"business_unit,omitempty"`
	CalledStationID          string     `json:"called_station_id,omitempty"`
	Dest                     string     `json:"dest,omitempty"`
	DestIP                   string     `json:"dest_ip,omitempty"`
	DestPort                 string     `json:"dest_port,omitempty"`
	DeviceType               string     `json:"device_type,omitempty"`
	Duration                 string     `json:"duration,omitempty"`
	EndpointMacAddress       string     `json:"endpoint_mac_address,omitempty"`
	EndpointProfile          string     `json:"endpoint_profile,omitempty"`
	Env                      string     `json:"env,omitempty"`
	EventTimestamp           string     `json:"event_timestamp,omitempty"`
	EventType                string     `json:"eventtype,omitempty"`
	FramedMtu                string     `json:"framed_mtu,omitempty"`
	Host                     string     `json:"host,omitempty"`
	HostIdentityGroup        string     `json:"host_identity_group,omitempty"`
	Hostname                 string     `json:"hostname,omitempty"`
	IdentifyPolicyRule       string     `json:"identify_policy_rule,omitempty"`
	IsePolicySet             string     `json:"ise_policy_set,omitempty"`
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
	PostureAssessment        string     `json:"posture_assessment,omitempty"`
	Protocol                 string     `json:"protocol,omitempty"`
	RadiusFlowType           string     `json:"radius_flow_type,omitempty"`
	RadiusStepData           string     `json:"radius_step_data,omitempty"`
	Response                 string     `json:"response,omitempty"`
	SelectedAuthIDStore      string     `json:"selected_auth_id_store,omitempty"`
	SelectionRuleMatch       string     `json:"selection_rule_match,omitempty"`
	ServiceType              string     `json:"service_type,omitempty"`
	Signature                string     `json:"signature,omitempty"`
	Src                      string     `json:"src,omitempty"`
	Ssid                     string     `json:"ssid,omitempty"`
	Time                     time.Time  `json:"time,omitempty"`
	TunnelMediumType         string     `json:"tunnel_medium_type,omitempty"`
	TunnelPrivateGroupID     string     `json:"tunnel_private_group_id,omitempty"`
	TunnelType               string     `json:"tunnel_type,omitempty"`
	User                     string     `json:"user,omitempty"`
	UserCategory             string     `json:"user_category,omitempty"`
	WlanID                   string     `json:"wlan_id,omitempty"`
}

type HostLookupAllowedProtocolsLogMessage struct {
}
