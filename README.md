# CISCO ISE Log Parser - Golang

## Adding new fields to the message parser

For certain types, this can be a one or two line change. If the field you want to parse is in the retrieveParseFn switch, simply add it to the LogMessage struct. The parser will parse with the existing generic parse function. If the field has a name that won't be auto-formatted to the Upper-camel-case style by the formatKey function, map the JSON field name from the message CSV to the correctly formatted struct field name.

If your field requires more complicated parsing, you will need to write a parse function that meets the valueParseFn definition, and then map the JSON field name to your custom parse function in the keyValueParseFuncMap. You can see examples of how to this by looking at the parseCiscoAVPair function.

If you don't plan on forking this repo, you can find any field not included in the existing LogMessage struct in the UnexpectedFields map in the MessageDetails field. The key will be the JSON field name found in the message CSV.