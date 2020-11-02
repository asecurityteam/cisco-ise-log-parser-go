package pkg

import (
	"encoding/json"
	"fmt"
)

type iseLogStruct interface{}

// UnmarshalCiscoIseLog consumes a byte array of a CISCO ISE log and unmarshals
// it into the given struct.
//
// Top level fields are unmarshaled via go's built-in json-tag driven unmarshalling,
// except for the Message field, which is parsed from a CSV into a Go struct.
func UnmarshalCiscoIseLog(log []byte, logStruct *iseLogStruct) error {

	err := json.Unmarshal(log, logStruct)
	if err != nil {
		return err
	}

	message, err := getMessageFromIseLogStruct(logStruct)
	if err != nil {
		return err
	}

	err = ParseIseLogMessageCSV(message, logStruct)
	if err != nil {
		return err
	}

	return nil
}

func ParseIseLogMessageCSV(message string, logStruct *iseLogStruct) error {
	// Add reflect magic here
	return nil
}

func getMessageFromIseLogStruct(iseLogStruct *iseLogStruct) (string, error) {
	message := getValueFromObject(iseLogStruct, "Message")
	if stringMessage, ok := message.(string); !ok {
		return stringMessage, nil
	}
	return "", fmt.Errorf("failed to parse message field since 'Message' field could not be found in object")
}

func getValueFromObject(object interface{}, field string) interface{} {
	// Add reflect magic here
	return "SAMPLE"
}
