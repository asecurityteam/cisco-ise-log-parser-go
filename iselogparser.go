package ciscoiselogparser

import (
	"encoding/json"
	"errors"
)

const (
	eapPeapAllowedProtocols = "EAP-PEAP-ALLOWED-PROTOCOLS"
    hostLookupAllowedProtocols = "HOST-LOOKUP-ALLOWED-PROTOCOLS"
	papAllowedProtocols = "PAP-ALLOWED-PROTOCOLS"
)


type iseLogAccessService struct {
	AccessService string `json:"access_service,omitempty"`
	EventLog
}

type EventLog interface{}

// UnmarshalJSON for *iseLogAccessService
func (iseLog *iseLogAccessService) UnmarshalJSON(data []byte) error {
	type Alias iseLogAccessService
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
