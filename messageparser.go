package ciscoiselogparser

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// Consts

// IseLogEvent is the type for the pseudo-enum describing various ISE log events.
type IseLogEvent int

// Event codes for Cisco ISE logs.
const (
	RADIUSAccountingStartRequest           IseLogEvent = 3000
	RADIUSAccountingStopRequest            IseLogEvent = 3001
	RADIUSAccountingWatchdogUpdate         IseLogEvent = 3002
	AuthenticationSucceeded                IseLogEvent = 5200
	AuthenticationFailed                   IseLogEvent = 5400
	SupplicantStoppedResponding            IseLogEvent = 5411
	EndpointConductedFailedAuthentications IseLogEvent = 5434
	EndpointRestartedEAPSession            IseLogEvent = 5440
	InfoProfilerEndpoint                   IseLogEvent = 80002
)

var eventTypeMap = map[string]IseLogEvent{
	"3000 NOTICE Radius-Accounting":     RADIUSAccountingStartRequest,
	"3001 NOTICE Radius-Accounting":     RADIUSAccountingStopRequest,
	"3002 NOTICE Radius-Accounting":     RADIUSAccountingWatchdogUpdate,
	"5200 NOTICE Passed-Authentication": AuthenticationSucceeded,
	"5400 NOTICE Failed-Attempt":        AuthenticationFailed,
	"5411 NOTICE Failed-Attempt":        SupplicantStoppedResponding,
	"5434 NOTICE RADIUS":                EndpointConductedFailedAuthentications,
	"5440 NOTICE RADIUS":                EndpointRestartedEAPSession,
	"80002 INFO  Profiler":              InfoProfilerEndpoint,
}

// StrToIseLogEvent converts the text label of an ISE log's CVS message to an enum.
func StrToIseLogEvent(event string) IseLogEvent {
	for description, code := range eventTypeMap {
		if strings.Contains(event, description) {
			return code
		}
	}
	return 0
}

// String converts an IseLogEvent enum into it's associated text.
func (i *IseLogEvent) String() string {
	for k, v := range eventTypeMap {
		if v == *i {
			return k
		}
	}
	return ""
}

// variableDictionary maps the field names in the CSV message to upper camel-case equivalents.
var variableDictionary = map[string]string{
	"ac-user-agent":           "ACUserAgent",
	"allowEasyWiredSession":   "AllowEasyWiredSession",
	"audit-session-id":        "AuditSessionID",
	"cisco-av-pair":           "CiscoAVPair",
	"device-mac":              "DeviceMAC",
	"device-platform":         "DevicePlatform",
	"device-public-mac":       "DevicePublicMAC",
	"device-platform-version": "DevicePlatformVersion",
	"device-type":             "DeviceType",
	"device-uid":              "DeviceUID",
	"l":                       "LocationL",
	"employeeID":              "EmployeeID",
	"mdm-tlv":                 "MDMTLV",
	"business_unit":           "BusinessUnit",
	"NAS-Port-Id":             "NASPortID",
	"Acct-Session-Id":         "AcctSessionID",
	"service-type":            "ServiceType",
	"NetworkDeviceProfileID":  "NetworkDeviceProfileID",
	"ConfigVersionId":         "ConfigVersionID",
	"profile-name":            "ProfileName",
	"sysDescr":                "SysDescription",
	"hrDeviceDescr":           "HRDeviceDescription",
	"EndpointMacAddress":      "EndPointMACAddress",
	"username":                "UserName",
	"User-Name":               "UserDashName",
}

// Structs

// LogMessage is a structure populated with the CSV field information from the message field of an ISE log.
type LogMessage struct {
	ADErrorDetails                       *string        `json:",omitempty"`
	ADFetchHostName                      *string        `json:",omitempty"`
	ADGroupsNames                        *string        `json:",omitempty"`
	ADOperatingSystem                    *string        `json:",omitempty"`
	ADUserCandidateIdentities            *string        `json:",omitempty"`
	ADUserDNSDomain                      *string        `json:",omitempty"`
	ADUserJoinPoint                      *string        `json:",omitempty"`
	ADUserNetBiosName                    *string        `json:",omitempty"`
	ADUserQualifiedName                  *string        `json:",omitempty"`
	ADUserResolvedDNS                    *string        `json:",omitempty"`
	ADUserResolvedIdentities             *string        `json:",omitempty"`
	ADUserSamAccountName                 *string        `json:",omitempty"`
	AKI                                  *string        `json:",omitempty"`
	AcctAuthentic                        *string        `json:",omitempty"`
	AcctDelayTime                        *string        `json:",omitempty"`
	AcctInputGigawords                   *string        `json:",omitempty"`
	AcctOutputGigawords                  *string        `json:",omitempty"`
	AcctInputOctets                      *string        `json:",omitempty"`
	AcctInputPackets                     *string        `json:",omitempty"`
	AcctOutputOctets                     *string        `json:",omitempty"`
	AcctOutputPackets                    *string        `json:",omitempty"`
	AcctSessionID                        *string        `json:",omitempty"`
	AcctSessionTime                      *string        `json:",omitempty"`
	AcctStatusType                       *string        `json:",omitempty"`
	AcctTerminateCause                   *string        `json:",omitempty"`
	AcsSessionID                         *string        `json:",omitempty"` // Ex. syd-isepsn01/386885261/12111391
	AllowEasyWiredSession                *bool          `json:",omitempty"`
	AllowedProtocolMatchedRule           *string        `json:",omitempty"`
	AirespaceWlanID                      *string        `json:",omitempty"`
	AuthenticationIdentityStore          *string        `json:",omitempty"`
	AuthenticationMethod                 *string        `json:",omitempty"`
	AuthenticationStatus                 *string        `json:",omitempty"`
	AuthorizationPolicyMatchedRule       *string        `json:",omitempty"`
	BusinessUnit                         *string        `json:",omitempty"`
	BYODRegistration                     *string        `json:",omitempty"`
	CPMSessionID                         *string        `json:",omitempty"`
	CVPN3000ASAPIX7xClientType           *string        `json:",omitempty"`
	CVPN3000ASAPIX7xSessionSubtype       *string        `json:",omitempty"`
	CVPN3000ASAPIX7xSessionType          *string        `json:",omitempty"`
	CVPN3000ASAPIX7xTunnelGroupName      *string        `json:",omitempty"` // Ex. byod
	CalledStationID                      []string       `json:",omitempty"`
	CacheUpdateTime                      *string        `json:",omitempty"`
	CallingStationID                     []string       `json:",omitempty"`
	ChargeableUserIdentity               *string        `json:",omitempty"`
	CiscoAVPair                          *CiscoAVPair   `json:",omitempty"`
	Class                                []string       `json:",omitempty"`
	Company                              *string        `json:",omitempty"`
	ConfigVersionID                      *string        `json:",omitempty"`
	CreateTime                           *string        `json:",omitempty"`
	CurrentIDStoreName                   *string        `json:",omitempty"`
	DC                                   []string       `json:",omitempty"`
	DeviceIdentifier                     *string        `json:",omitempty"`
	DTLSSupport                          *string        `json:",omitempty"`
	DaysToExpiry                         *string        `json:",omitempty"`
	Department                           *string        `json:",omitempty"`
	DevicePlatform                       *string        `json:",omitempty"`
	DestinationIPAddress                 *string        `json:",omitempty"`
	DestinationPort                      *string        `json:",omitempty"`
	Description                          *string        `json:",omitempty"`
	DetailedInfo                         *string        `json:",omitempty"`
	DeviceIPAddress                      *string        `json:",omitempty"` // Ex. 86.75.30.9
	DevicePort                           *string        `json:",omitempty"`
	DeviceRegistrationStatus             *string        `json:",omitempty"`
	DeviceType                           *DropDown      `json:",omitempty"` // Ex. All Device Types -> Cisco -> Firewall
	DistinguishedName                    *string        `json:",omitempty"`
	EapAuthentication                    *string        `json:",omitempty"`
	EapTunnel                            *string        `json:",omitempty"`
	EAPKeyName                           *string        `json:",omitempty"`
	EapChainingResult                    *string        `json:",omitempty"`
	EmployeeID                           *string        `json:",omitempty"`
	EndpointCertainityMetric             *string        `json:",omitempty"`
	EndpointIdentityGroup                *string        `json:",omitempty"`
	EndPointMACAddress                   *string        `json:",omitempty"`
	EndPointMatchedProfile               *string        `json:",omitempty"`
	EndpointMatchedPolicy                *string        `json:",omitempty"` // Ex. Printer, Apple-Device
	EndpointPolicy                       *string        `json:",omitempty"`
	EndPointPolicyID                     *string        `json:",omitempty"`
	EndpointIPAddress                    *string        `json:",omitempty"`
	EndpointNADAddress                   *string        `json:",omitempty"`
	EndpointProperty                     *LogMessage    `json:",omitempty"`
	EndpointOUI                          *string        `json:",omitempty"` // Ex. Apple, INC
	EndpointSourceEvent                  *string        `json:",omitempty"`
	EventTimestamp                       *string        `json:",omitempty"`
	EventDescription                     *string        `json:",omitempty"`
	EventType                            *IseLogEvent   `json:",omitempty"`
	ExtendedKeyUsageName                 []string       `json:",omitempty"`
	ExtendedKeyUsageOID                  []string       `json:",omitempty"`
	ExternalGroups                       []string       `json:",omitempty"`
	FailureReason                        *string        `json:",omitempty"`
	FirstCollection                      *string        `json:",omitempty"`
	FeedService                          *bool          `json:",omitempty"`
	FramedIPAddress                      *string        `json:",omitempty"`
	FramedMTU                            *string        `json:",omitempty"`
	FramedProtocol                       *string        `json:",omitempty"`
	HRDeviceDescription                  *string        `json:",omitempty"`
	HostIdentityGroup                    *string        `json:",omitempty"`
	Hostname                             *string        `json:",omitempty"`
	IPSEC                                *DropDown      `json:",omitempty"`
	ISEPolicySetName                     *string        `json:",omitempty"`
	IdentityAccessRestricted             *string        `json:",omitempty"`
	IdentityGroup                        *string        `json:",omitempty"`
	IdentityGroupID                      *string        `json:",omitempty"`
	IdentityPolicyMatchedRule            *string        `json:",omitempty"`
	IdentitySelectionMatchedRule         *string        `json:",omitempty"`
	IsEndpointInRejectMode               *bool          `json:",omitempty"`
	IsMachineAuthentication              *bool          `json:",omitempty"`
	IsMachineIdentity                    *bool          `json:",omitempty"`
	IsThirdPartyDeviceFlow               *bool          `json:",omitempty"`
	Issuer                               *string        `json:",omitempty"`
	IssuerCommonName                     *string        `json:",omitempty"`
	IssuerDomainComponent                []string       `json:",omitempty"`
	KeyUsage                             []string       `json:",omitempty"`
	LastActivity                         *string        `json:",omitempty"`
	LastNmapScanTime                     *string        `json:",omitempty"`
	LicenseTypes                         *string        `json:",omitempty"`
	Location                             *DropDown      `json:",omitempty"`
	LocationL                            *string        `json:",omitempty"`
	LocationCapable                      *string        `json:",omitempty"`
	MatchedPolicyID                      *string        `json:",omitempty"`
	MessageCode                          *string        `json:",omitempty"`
	MDMServerID                          *string        `json:",omitempty"`
	ModelName                            *string        `json:",omitempty"`
	NASIPAddress                         *string        `json:",omitempty"`
	NASIdentifier                        *string        `json:",omitempty"`
	NASPort                              *string        `json:",omitempty"`
	NASPortID                            *string        `json:",omitempty"`
	NASPortType                          *string        `json:",omitempty"`
	Name                                 *string        `json:",omitempty"`
	NetworkDeviceProfile                 *string        `json:",omitempty"`
	NetworkDeviceGroups                  DropDownMap    `json:",omitempty"`
	NetworkDeviceName                    *string        `json:",omitempty"`
	NetworkDeviceProfileID               *string        `json:",omitempty"`
	NetworkDeviceProfileName             *string        `json:",omitempty"`
	NmapScanCount                        *int           `json:",omitempty"`
	OU                                   *string        `json:",omitempty"`
	OperatingSystem                      *string        `json:",omitempty"`
	OriginalUserName                     *string        `json:",omitempty"`
	PhoneID                              *string        `json:",omitempty"`
	PostureApplicable                    *string        `json:",omitempty"`
	PostureAssessmentStatus              *string        `json:",omitempty"`
	PostureExpiry                        *string        `json:",omitempty"`
	PolicyVersion                        *string        `json:",omitempty"`
	ProfilerServer                       *string        `json:",omitempty"`
	Protocol                             *string        `json:",omitempty"`
	PortalUser                           *string        `json:",omitempty"`
	QueryResult                          *string        `json:",omitempty"`
	RadiusFlowType                       *string        `json:",omitempty"`
	RadiusPacketType                     *string        `json:",omitempty"`
	RegistrationTimeStamp                *string        `json:",omitempty"`
	RequestLatency                       *int           `json:",omitempty"`
	Response                             *LogMessage    `json:",omitempty"`
	Role                                 *DropDown      `json:",omitempty"`
	SSID                                 *string        `json:",omitempty"`
	SAMAccountName                       *string        `json:",omitempty"`
	Security                             *DropDown      `json:",omitempty"`
	SelectedAccessService                *string        `json:",omitempty"`
	SelectedAuthenticationIdentityStores *string        `json:",omitempty"`
	SelectedAuthorizationProfiles        *string        `json:",omitempty"`
	SessionTimeout                       *string        `json:",omitempty"`
	ServiceType                          *string        `json:",omitempty"`
	SoftwareVersion                      *string        `json:",omitempty"`
	State                                []string       `json:",omitempty"`
	StaticAssignment                     *bool          `json:",omitempty"`
	StaticGroupAssignment                *bool          `json:",omitempty"`
	Step                                 []string       `json:",omitempty"`
	StepData                             *string        `json:",omitempty"`
	StepLatency                          *string        `json:",omitempty"`
	Subject                              *string        `json:",omitempty"`
	SubjectAlternativeName               *string        `json:",omitempty"`
	SubjectAlternativeNameEmail          *string        `json:",omitempty"`
	SubjectAlternativeNameOtheName       *string        `json:",omitempty"`
	SubjectCommonName                    *string        `json:",omitempty"`
	SysDescription                       *string        `json:",omitempty"`
	TLSCipher                            *string        `json:",omitempty"`
	TLSVersion                           *string        `json:",omitempty"`
	Team                                 *DropDown      `json:",omitempty"`
	TemplateName                         *string        `json:",omitempty"`
	TerminationAction                    *string        `json:",omitempty"`
	TimeToProfile                        *string        `json:",omitempty"`
	TotalCertaintyFactor                 *string        `json:",omitempty"`
	TotalFailedAttempts                  *int           `json:",omitempty"`
	TotalFailedTime                      *int           `json:",omitempty"`
	TunnelClientEndpoint                 *string        `json:",omitempty"`
	TunnelMediumType                     *string        `json:",omitempty"`
	TunnelPrivateGroupID                 *string        `json:",omitempty"`
	TunnelType                           *string        `json:",omitempty"`
	Type                                 *string        `json:",omitempty"`
	Undefined151                         *string        `json:",omitempty"`
	UniqueSubjectID                      *string        `json:",omitempty"`
	UseCase                              *string        `json:",omitempty"`
	UserAccountControl                   *string        `json:",omitempty"`
	UserName                             *string        `json:",omitempty"` // Ex. bwayne
	UserDashName                         *string        `json:",omitempty"` // User-Name not to be confused with UserName
	UserFetchCountryName                 *string        `json:",omitempty"`
	UserFetchEmail                       *string        `json:",omitempty"`
	UserFetchFirstName                   *string        `json:",omitempty"`
	UserFetchJobTitle                    *string        `json:",omitempty"`
	UserFetchLastName                    *string        `json:",omitempty"`
	UserFetchUserName                    *string        `json:",omitempty"`
	UserFetchStreetAddress               *string        `json:",omitempty"`
	UserFetchTelephone                   *string        `json:",omitempty"`
	UserType                             *string        `json:",omitempty"`
	UpdateTime                           *string        `json:",omitempty"`
	MessageDetails                       MessageDetails `json:",omitempty"`
}

// CiscoAVPair contains subfields derived from the cisco-av-pair field of an ISE log's message CSV content.
type CiscoAVPair struct {
	MDMTLV          *MDMTLV `json:",omitempty"`
	AuditSessionID  *string `json:",omitempty"`
	SourceIP        *string `json:",omitempty"`
	COAPush         *string `json:",omitempty"`
	ProfileName     *string `json:",omitempty"`
	MDNS            *string `json:",omitempty"`
	ConnectProgress *string `json:",omitempty"`
	DiscCauseExt    *string `json:",omitempty"`
	Method          *string `json:",omitempty"`
	ServiceType     *string `json:",omitempty"`
}

// MDMTLV contains subfields derived from the mdm-tlv field of an ISE log's message CSV content.
type MDMTLV struct {
	DevicePlatform        *string `json:",omitempty"` // Ex. linux-64, win, mac-intel
	DevicePlatformVersion *string `json:",omitempty"` // Ex. 10.15.7
	DeviceMAC             *string `json:",omitempty"` // Ex. 3c-22-fb-00-6a-14
	DevicePublicMAC       *string `json:",omitempty"`
	DeviceType            *string `json:",omitempty"` // Ex. MacBookPro15\,2
	DeviceUID             *string `json:",omitempty"`
	DeviceUIDGlobal       *string `json:",omitempty"`
	ACUserAgent           *string `json:",omitempty"`
}

// DropDown is a linked list used to describe data that follows a dropdown struct.
// Ex. All vegetables -> Orange vegetables -> Carrots
type DropDown struct {
	Value string    `json:",omitempty"`
	Child *DropDown `json:",omitempty"`
}

// String stringifies a DropDown object.
func (n *DropDown) String() string {
	if n.Child != nil {
		return n.Value + " -> " + n.Child.String()
	}
	return n.Value
}

// Slice converts a DropDown object into a slice.
func (n *DropDown) Slice() []string {
	if n.Child != nil {
		return append([]string{n.Value}, n.Child.Slice()...)
	}
	return []string{n.Value}
}

// Last returns the furthest option in a DropDown.
func (n *DropDown) Last() string {
	if n.Child != nil {
		return n.Child.Last()
	}
	return n.Value
}

// DropDownMap is map of strings-to-DropDown objects.
// Ex. {Vegetables: All vegetables -> Orange vegetables -> Carrots, Fruits: All Fruits -> Red fruits -> Apples}
type DropDownMap map[string]DropDown

// String stringifies a DropDownMap.
func (n *DropDownMap) String() string {
	if len(*n) == 0 {
		return "{}"
	}
	str := "{"
	for k, v := range *n {
		str = fmt.Sprintf("%s%s: %s, ", str, k, v.String())
	}
	str = str[:len(str)-2] + "}"
	return str
}

// MessageDetails contains details about the message CSV.
type MessageDetails struct {
	UnexpectedFields map[string]string
}

// UnmarshalJSON for *LogMessage
func (logMessage *LogMessage) UnmarshalJSON(data []byte) error {
	type Alias LogMessage
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(logMessage),
	}

	err := json.Unmarshal(data, &aux)
	if err == nil {
		return nil
	}
	// if json.Unmarshal results in an error, then it's in CSV format, so use the CSV parser
	err = ParseMessageCSV(string(data), logMessage)
	if err != nil {
		return err
	}
	return nil
}

// valueParseFn defines the standard parse function for a given field.
type valueParseFn func(logMessage *LogMessage, key string, value string) error

// parseFnMap maps JSON field keys found in the message CSV to valueParseFn functions that are used to populate the LogMessage struct.
type parseFnMap map[string]valueParseFn

var keyValueParseFuncMap = parseFnMap{
	"#015":             parseDisregard,
	"cisco-av-pair":    parseCiscoAVPair,
	"EndpointProperty": parseEndpointProperty,
	"Response":         parseResponse,
}

// retrieveParseFn checks the parseMap for any custom functions for a given key, and if one cannot be found, attempts to return a generic parse function.
func (pmap *parseFnMap) retrieveParseFn(object interface{}, key string) valueParseFn {
	parseMap := *pmap
	parseFunc := parseStringKeyValue
	if parseFn, ok := parseMap[key]; ok {
		parseFunc = parseFn
	} else {
		formattedKey := formatKey(key)
		switch getFieldType(object, formattedKey).(type) {
		case *int:
			parseFunc = parseIntKeyValue
		case *IseLogEvent:
			parseFunc = parseIseLogEventValue
		case []string:
			parseFunc = parseAppendStringToList
		case *bool:
			parseFunc = parseBoolKeyValue
		case *DropDown:
			parseFunc = parseDropDownList
		case DropDownMap:
			parseFunc = parseDropDownListMap
		}
	}
	return parseFunc
}

// ParseMessageCSV consumes the CSV formatted text used in the message field of a CISCO ISE Log and returns a Go struct with the given information.
func ParseMessageCSV(log string, iselogmessage *LogMessage) (err error) {

	iselogmessage.MessageDetails.UnexpectedFields = map[string]string{}
	iselogmessage.NetworkDeviceGroups = DropDownMap{}

	_, columns, err := structureLog(log)
	if err != nil {
		return &ParseError{
			OrigErr: err,
			Message: "parse-structure-error",
			Reason:  "log message has unexpected structure",
		}
	}
	for _, column := range columns {
		err = parseField(iselogmessage, column, keyValueParseFuncMap)
		if err != nil {
			return err
		}
	}

	return nil
}

func parseField(logMessage *LogMessage, column string, parseMap parseFnMap) error {
	key, value := extractKeyValue(column)
	parseFunc := parseMap.retrieveParseFn(logMessage, key)
	err := parseFunc(logMessage, formatKey(key), value)
	if err != nil {
		if assignmentFailure, ok := err.(*AssignmentFailure); ok && strings.Contains(assignmentFailure.Message, "invalid-value") {
			addUnexpectedKeyValue(logMessage, key, value)
			return nil
		}
		return &ParseError{
			OrigErr: err,
			Message: "parse-field-error",
			Reason:  fmt.Sprintf("could not parse key - value: %s - %v", key, value),
		}
	}
	return nil
}

// Parse Functions

// parseDisregard can be used to ignored certain keys.
func parseDisregard(logMessage *LogMessage, key string, value string) error {
	return nil
}

func parseStringKeyValue(logMessage *LogMessage, key string, value string) error {
	return setField(logMessage, key, &value)
}

func parseBoolKeyValue(logMessage *LogMessage, key string, value string) error {
	trueReferrable := true
	falseReferrable := false
	switch strings.ToLower(value) {
	case "false":
		return setField(logMessage, key, &falseReferrable)
	case "true":
		return setField(logMessage, key, &trueReferrable)
	default:
		return &TypeMismatch{
			Original: strings.ToLower(value),
			Type:     "bool",
		}
	}
}

func parseIntKeyValue(logMessage *LogMessage, key string, value string) error {
	intVal, err := strconv.Atoi(value)
	if err != nil {
		return &TypeMismatch{
			Original: value,
			Type:     "int",
		}
	}

	return setField(logMessage, key, &intVal)
}

func parseIseLogEventValue(logMessage *LogMessage, key string, value string) error {
	intVal, err := strconv.Atoi(value)
	if err != nil {
		return &TypeMismatch{
			Original: value,
			Type:     "int",
		}
	}
	iseLogEvent := IseLogEvent(intVal)

	return setField(logMessage, key, &iseLogEvent)
}

// parseAppendStringToList parses an individual string value and adds it to a slice object in the LogMessage struct.
func parseAppendStringToList(logMessage *LogMessage, key string, value string) error {
	return appendToSlice(logMessage, key, []string{value})
}

func parseDropDownList(logMessage *LogMessage, key string, value string) error {
	dropDown, _, err := createDropDown(value)
	if err != nil {
		return err
	}

	return setField(logMessage, key, &dropDown)
}

func parseDropDownListMap(logMessage *LogMessage, key string, value string) error {
	dropDown, mapKey, err := createDropDown(value)
	if err != nil {
		return err
	}

	return addToMap(logMessage, key, mapKey, dropDown)
}

// parseCiscoAVPair is a custom function to parse the cisco-av-pair field into the CiscoAVPair field of the LogMessage struct.
func parseCiscoAVPair(logMessage *LogMessage, key string, value string) error {
	if logMessage.CiscoAVPair == nil {
		logMessage.CiscoAVPair = &CiscoAVPair{}
	}

	ciscoAVPairSlice := strings.Split(value, "=")
	if len(ciscoAVPairSlice) < 2 {
		return &TypeMismatch{
			Original: ciscoAVPairSlice,
			Type:     "CiscoAVPair",
		}
	}
	formattedKey := formatKey(ciscoAVPairSlice[0])

	switch formattedKey {
	case "MDMTLV":
		if len(ciscoAVPairSlice) < 3 {
			return &TypeMismatch{
				Original: ciscoAVPairSlice,
				Type:     "MDMTLV",
			}
		}
		if logMessage.CiscoAVPair.MDMTLV == nil {
			logMessage.CiscoAVPair.MDMTLV = &MDMTLV{}
		}
		return setField(logMessage.CiscoAVPair.MDMTLV, formatKey(ciscoAVPairSlice[1]), &ciscoAVPairSlice[2])
	default:
		return setField(logMessage.CiscoAVPair, formattedKey, &ciscoAVPairSlice[1])
	}
}

// parseResponse is a custom function to parse the Response field into the Response field of the LogMessage struct.
func parseResponse(logMessage *LogMessage, key string, value string) error {

	response := &LogMessage{
		MessageDetails: MessageDetails{
			UnexpectedFields: map[string]string{},
		},
	}

	if value == "" {
		// Nothing to parse
		return nil
	}

	value = strings.ReplaceAll(value, " ", "")
	responseParts := strings.FieldsFunc(value, func(r rune) bool {
		return r == '{' || r == '}'
	})

	if len(responseParts) == 0 {
		// Nothing to parse
		return nil
	}

	// Each column becomes one key-value pair
	columns := strings.Split(responseParts[0], ";")

	// Parse function map used for the Response type
	parseMap := parseFnMap{
		"cisco-av-pair": parseCiscoAVPair,
	}

	for _, column := range columns {
		key, value := extractKeyValue(column)

		if key == "" && value == "" {
			continue
		}

		parseFunc := parseMap.retrieveParseFn(response, key)
		err := parseFunc(response, formatKey(key), value)
		if err != nil {
			if assignmentFailure, ok := err.(*AssignmentFailure); ok && strings.Contains(assignmentFailure.Message, "invalid-value") {
				addUnexpectedKeyValue(response, key, value)
				continue
			}
			return &ParseError{
				OrigErr: err,
				Message: "parse-field-error",
				Reason:  fmt.Sprintf("could not parse key - value: %s - %v", key, value),
			}
		}
	}

	logMessage.Response = response
	return nil
}

// parseEndpointProperty is a custom function to parse the EndpointProperty field into the EndpointProperty field of the LogMessage struct
func parseEndpointProperty(logMessage *LogMessage, key string, value string) error {

	endpointProperty := &LogMessage{
		MessageDetails: MessageDetails{
			UnexpectedFields: map[string]string{},
		},
	}
	endpointProperty.NetworkDeviceGroups = DropDownMap{}

	value = strings.ReplaceAll(value, `\, `, "{COMMA}") // replace certain commas with "{COMMA}" so that we don't split by it
	endpointPropertySlice := strings.Split(value, `\,`)
	if len(endpointPropertySlice) == 0 {
		return &TypeMismatch{
			Original: endpointPropertySlice,
			Type:     "EndpointProperty",
		}
	}

	var keyValueEndpointPropertyFuncMap = parseFnMap{
		"#015":          parseDisregard,
		"cisco-av-pair": parseCiscoAVPair,
		"device-type":   parseDisregard, // Different type than LogMessage's DeviceType, so ignore
		"Response":      parseResponse,
		"Location":      parseDisregard, // Different type than LogMessage's Location, so ignore
	}

	for _, column := range endpointPropertySlice {
		column = strings.ReplaceAll(column, "{COMMA}", `\, `) // restore the commas from earlier now that the endpointProperty has been split
		key, value := extractKeyValue(column)

		parseFunc := keyValueEndpointPropertyFuncMap.retrieveParseFn(endpointProperty, key)
		err := parseFunc(endpointProperty, formatKey(key), value)
		if err != nil {
			if assignmentFailure, ok := err.(*AssignmentFailure); ok && strings.Contains(assignmentFailure.Message, "invalid-value") {
				addUnexpectedKeyValue(endpointProperty, key, value)
				continue
			}
			return &ParseError{
				OrigErr: err,
				Message: "parse-field-error",
				Reason:  fmt.Sprintf("could not parse key - value: %s - %v", key, value),
			}
		}
	}

	logMessage.EndpointProperty = endpointProperty

	return nil
}

// createDropDown converts a value of the format: "Location#Location#All Locations#Washington#Portland"
// into a DropDown object: "All Locations -> Washington -> Portland".
func createDropDown(dropDownText string) (dropDown DropDown, key string, err error) {
	dropDownSlice := strings.Split(dropDownText, "#")
	if len(dropDownSlice) < 2 {
		return DropDown{}, "", &TypeMismatch{
			Original: dropDownText,
			Type:     "DropDown",
		}
	}
	key = dropDownSlice[0]
	dropDownSlice = dropDownSlice[1:]
	parent := &DropDown{
		Value: dropDownSlice[0],
	}
	curNode := parent
	for i := 1; i < len(dropDownSlice); i++ {
		newNode := &DropDown{
			Value: dropDownSlice[i],
		}
		curNode.Child = newNode
		curNode = newNode
	}
	return *parent, key, nil
}

// Parsing Utilities

// extractKeyValue splits a piece of text on the first "=" and returns both halves as the key and value.
func extractKeyValue(column string) (key string, value string) {
	splitColumn := strings.SplitN(column, "=", 2)
	if len(splitColumn) != 2 {
		return column, ""
	}
	return splitColumn[0], splitColumn[1]
}

// removals is a list of characters we remove when attempted to autoformat a field name.
var removals = []string{
	"-", " ", "/",
}

// formatKey checks if a field name is mapped in the variableDictionary, and if not, attempts to autoformat the key.
func formatKey(key string) string {
	if match, ok := variableDictionary[key]; ok {
		return match
	}
	for _, removal := range removals {
		key = strings.ReplaceAll(key, removal, "")
	}
	titleCase := cases.Title(language.Und)
	return titleCase.String(key)
}

// addUnexpectedKeyValue adds fields that do not currently exist in our Go struct into the UnexpectedFields map
func addUnexpectedKeyValue(logMessage *LogMessage, field string, value string) {
	logMessage.MessageDetails.UnexpectedFields[field] = value
}

// structureLog converts a csv-formatted string into slice of fields that we can then parse into a struct.
func structureLog(rawLog string) (title string, fields []string, err error) {
	sectionSplit := strings.SplitN(rawLog, ": ", 2) // ex. separate  "3002 NOTICE Radius-Accounting" from the rest of the string
	if len(sectionSplit) != 2 {
		return "", []string{}, &UnprocessableMessageFailure{
			Message:    "invalid-message-format",
			Reason:     "",
			LogMessage: rawLog,
		}
	}
	title = sectionSplit[0] // ex. "3002 NOTICE Radius-Accounting"

	body := sectionSplit[1]
	body = strings.ReplaceAll(body, ",#015", ", #015") // fix end of log so it can be split correctly
	body = strings.ReplaceAll(body, `\,`, "{COMMA}")   // replace escaped commas with "{COMMA}" so that we can split by "," later.
	body = strings.ReplaceAll(body, `\;`, "{SEMICOLON}")

	// Converts the message CSV title into parsible fields in the message body.
	body = fmt.Sprintf("EventType=%d, EventDescription=%s", StrToIseLogEvent(title), body)

	fields = strings.Split(body, ", ")
	for i := range fields {
		fields[i] = strings.ReplaceAll(strings.ReplaceAll(fields[i], "{COMMA}", `\,`), "{SEMICOLON}", `\;`)
	}
	return title, fields, nil
}

// Reflection Utilities

// setField attempts to set given field on a given object with a given value.
func setField(object interface{}, field string, value interface{}) error {
	ps := reflect.ValueOf(object)

	s := ps.Elem()

	if s.Kind() == reflect.Struct {
		f := s.FieldByName(field)
		val := reflect.ValueOf(value)
		if f.IsValid() {
			if f.CanSet() {
				if f.Kind() == val.Kind() {
					f.Set(val)
					return nil
				}
				return &AssignmentFailure{
					Message: "assignment-wrong-field-type",
					Reason:  fmt.Sprintf("%v cannot be set to %v", field, val),
				}
			}
			return &AssignmentFailure{
				Message: "assignment-cannot-bet-set",
				Reason:  fmt.Sprintf("%v cannot be set", field),
			}
		}
		return &AssignmentFailure{
			Message: "assignment-invalid-value",
			Reason:  fmt.Sprintf("%v is invalid", field),
		}
	}
	return &AssignmentFailure{
		Message: "assignment-not-a-struct",
		Reason:  fmt.Sprintf("%v is not a struct", s),
	}
}

// appendToSlice attempts to append a given value to a given slice field on a given object.
func appendToSlice(object interface{}, field string, value interface{}) error {
	ps := reflect.ValueOf(object)

	s := ps.Elem()

	if s.Kind() == reflect.Struct {
		f := s.FieldByName(field)
		val := reflect.ValueOf(value)
		if f.IsValid() {
			if f.CanSet() {
				if f.Kind() == val.Kind() {
					f.Set(reflect.AppendSlice(f, val))
					return nil
				}
				return &AssignmentFailure{
					Message: "assignment-slice-wrong-field-type",
					Reason:  fmt.Sprintf("%v cannot be set to %v", f, val),
				}
			}
			return &AssignmentFailure{
				Message: "assignment-slice-cannot-be-set",
				Reason:  fmt.Sprintf("%v cannot be set", f),
			}
		}
		return &AssignmentFailure{
			Message: "assignment-slice-invalid-value",
			Reason:  fmt.Sprintf("%v is not a valid value", f),
		}
	}
	return &AssignmentFailure{
		Message: "assignment-slice-not-a-struct",
		Reason:  fmt.Sprintf("%v is not a struct", s),
	}
}

// addToMap attempts to map a given key-value to a given map field on a given object.
func addToMap(object interface{}, field string, key string, value interface{}) error {
	ps := reflect.ValueOf(object)

	s := ps.Elem()

	if s.Kind() == reflect.Struct {
		f := s.FieldByName(field)
		k := reflect.ValueOf(key)
		val := reflect.ValueOf(value)
		if f.IsValid() {
			if f.CanSet() {
				if f.Kind() == reflect.Map {
					f.SetMapIndex(k, val)
					return nil
				}
				return &AssignmentFailure{
					Message: "assignment-map-wrong-field-type",
					Reason:  fmt.Sprintf("%v cannot be set to %v", f, val),
				}
			}
			return &AssignmentFailure{
				Message: "assignment-map-cannot-be-set",
				Reason:  fmt.Sprintf("%v cannot be set", f),
			}
		}
		return &AssignmentFailure{
			Message: "assignment-map-invalid-value",
			Reason:  fmt.Sprintf("%v is not a valid value", f),
		}
	}
	return &AssignmentFailure{
		Message: "assignment-map-not-a-struct",
		Reason:  fmt.Sprintf("%v is not a struct", s),
	}
}

// getFieldType returns a default object of the same type as the given field in the given object.
func getFieldType(object interface{}, field string) interface{} {
	ps := reflect.ValueOf(object)

	s := ps.Elem()

	if s.Kind() == reflect.Struct {
		f := s.FieldByName(field)
		if f.IsValid() {
			return f.Interface()
		}
		return nil
	}
	return nil
}

// Errors

// AssignmentFailure occurs when we fail to assign a value through reflection.
type AssignmentFailure struct {
	Message string
	Reason  string
}

func (a *AssignmentFailure) Error() string {
	return fmt.Sprintf("%s: failed to assign value during message parsing: %s", a.Message, a.Reason)
}

// ParseError occurs when we fail to parse a given field into a struct.
type ParseError struct {
	OrigErr error
	Message string
	Reason  string
}

func (p *ParseError) Error() string {
	return fmt.Sprintf("%s: %s: %s", p.Message, p.Reason, p.OrigErr.Error())
}

// TypeMismatch occurs when we attempt to parse a field that is not of the expected format or type.
type TypeMismatch struct {
	Original interface{}
	Type     string
}

func (t *TypeMismatch) Error() string {
	return fmt.Sprintf("%v is not a valid %s", t.Original, t.Type)
}

// UnprocessableMessageFailure occurs when a CSV message is formatted in a way our parser does not expect
type UnprocessableMessageFailure struct {
	Message    string
	Reason     string
	LogMessage string
}

func (u *UnprocessableMessageFailure) Error() string {
	return fmt.Sprintf("%s: could not parse message due to: %s", u.Message, u.Reason)
}
