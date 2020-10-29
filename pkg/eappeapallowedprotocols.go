package pkg

import "time"

type EAPPEAPAllowedProtocolsLog struct {
	AccessService            string                            `json:"access_service,omitempty"`
	AccountingAuthentication string                            `json:"accounting_authentication,omitempty"`
	AccountingSessionID      string                            `json:"accounting_session_id,omitempty"`
	AccountingStatusType     string                            `json:"accounting_status_type,omitempty"`
	AcsSessionID             string                            `json:"acs_session_id,omitempty"`
	Aggregator               string                            `json:"aggregator,omitempty"`
	AuditSessionID           string                            `json:"audit_session_id,omitempty"`
	BusinessUnit             string                            `json:"business_unit,omitempty"`
	CalledStationID          string                            `json:"called_station_id,omitempty"`
	Dest                     string                            `json:"dest,omitempty"`
	DeviceType               string                            `json:"device_type,omitempty"`
	Duration                 string                            `json:"duration,omitempty"`
	Env                      string                            `json:"env,omitempty"`
	EventType                string                            `json:"eventtype,omitempty"`
	Host                     string                            `json:"host,omitempty"`
	Hostname                 string                            `json:"hostname,omitempty"`
	Location                 string                            `json:"location,omitempty"`
	Logtype                  string                            `json:"logtype,omitempty"`
	Message                  EAPPEAPAllowedProtocolsLogMessage `json:"message,omitempty"`
	Mnemonic                 string                            `json:"mnemonic,omitempty"`
	NasIdentifier            string                            `json:"nas_identifier,omitempty"`
	NasIPAddress             string                            `json:"nas_ip_address,omitempty"`
	NasPort                  string                            `json:"nas_port,omitempty"`
	NasPortType              string                            `json:"nas_port_type,omitempty"`
	NetworkDeviceName        string                            `json:"network_device_name,omitempty"`
	NetworkDeviceProfile     string                            `json:"network_device_profile,omitempty"`
	Notice                   string                            `json:"notice,omitempty"`
	ServiceType              string                            `json:"service_type,omitempty"`
	Signature                string                            `json:"signature,omitempty"`
	Src                      string                            `json:"src,omitempty"`
	Time                     time.Time                         `json:"time,omitempty"`
	TunnelMediumType         string                            `json:"tunnel_medium_type,omitempty"`
	TunnelPrivateGroupID     string                            `json:"tunnel_private_group_id,omitempty"`
	TunnelType               string                            `json:"tunnel_type,omitempty"`
	User                     string                            `json:"user,omitempty"`
	WlanID                   string                            `json:"wlan_id,omitempty"`
}

type EAPPEAPAllowedProtocolsLogMessage struct {
}
