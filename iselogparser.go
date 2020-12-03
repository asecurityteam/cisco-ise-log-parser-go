package ciscoiselogparser

import (
	"encoding/json"
	"errors"
)

const (
	eapPeapAllowedProtocols    = "EAP-PEAP-ALLOWED-PROTOCOLS"
	hostLookupAllowedProtocols = "HOST-LOOKUP-ALLOWED-PROTOCOLS"
	papAllowedProtocols        = "PAP-ALLOWED-PROTOCOLS"
)

// IseLogAccessService contains the AccessService, which will determine the shape of the EventLog
type IseLogAccessService struct {
	AccessService string `json:"access_service,omitempty"`
	EventLog
}

// EventLog will either be a PAP Allowed Protocol, Host Lookup Allowed  Protocol, or EAP-PEAP Allowed Protocol Log
type EventLog interface{}

// UnmarshalJSON for *IseLogAccessService
func (iseLog *IseLogAccessService) UnmarshalJSON(data []byte) error {
	type Alias IseLogAccessService
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(iseLog),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	switch aux.AccessService {
	case papAllowedProtocols:
		var papProtocolISELog PAPAllowedProtocolsLog
		if err := json.Unmarshal(data, &papProtocolISELog); err != nil {
			return err
		}
		iseLog.EventLog = papProtocolISELog
	case hostLookupAllowedProtocols:
		var HostProtocolISELog HostLookupAllowedProtocolsLog
		if err := json.Unmarshal(data, &HostProtocolISELog); err != nil {
			return err
		}
		iseLog.EventLog = HostProtocolISELog
	case eapPeapAllowedProtocols:
		var EapProtocolISELog EAPPEAPAllowedProtocolsLog
		if err := json.Unmarshal(data, &EapProtocolISELog); err != nil {
			return err
		}
		iseLog.EventLog = EapProtocolISELog
	default:
		return errors.New("ISE Log Protocol was not found or is not supported")
	}
	return nil
}
