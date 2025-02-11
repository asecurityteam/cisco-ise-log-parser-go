# CISCO ISE Log Parser - Golang

[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=asecurityteam_cisco-ise-log-parser-go&metric=bugs)](https://sonarcloud.io/dashboard?id=asecurityteam_cisco-ise-log-parser-go)
[![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=asecurityteam_cisco-ise-log-parser-go&metric=code_smells)](https://sonarcloud.io/dashboard?id=asecurityteam_cisco-ise-log-parser-go)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=asecurityteam_cisco-ise-log-parser-go&metric=coverage)](https://sonarcloud.io/dashboard?id=asecurityteam_cisco-ise-log-parser-go)
[![Duplicated Lines (%)](https://sonarcloud.io/api/project_badges/measure?project=asecurityteam_cisco-ise-log-parser-go&metric=duplicated_lines_density)](https://sonarcloud.io/dashboard?id=asecurityteam_cisco-ise-log-parser-go)
[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=asecurityteam_cisco-ise-log-parser-go&metric=ncloc)](https://sonarcloud.io/dashboard?id=asecurityteam_cisco-ise-log-parser-go)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=asecurityteam_cisco-ise-log-parser-go&metric=sqale_rating)](https://sonarcloud.io/dashboard?id=asecurityteam_cisco-ise-log-parser-go)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=asecurityteam_cisco-ise-log-parser-go&metric=alert_status)](https://sonarcloud.io/dashboard?id=asecurityteam_cisco-ise-log-parser-go)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=asecurityteam_cisco-ise-log-parser-go&metric=reliability_rating)](https://sonarcloud.io/dashboard?id=asecurityteam_cisco-ise-log-parser-go)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=asecurityteam_cisco-ise-log-parser-go&metric=security_rating)](https://sonarcloud.io/dashboard?id=asecurityteam_cisco-ise-log-parser-go)
[![Technical Debt](https://sonarcloud.io/api/project_badges/measure?project=asecurityteam_cisco-ise-log-parser-go&metric=sqale_index)](https://sonarcloud.io/dashboard?id=asecurityteam_cisco-ise-log-parser-go)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=asecurityteam_cisco-ise-log-parser-go&metric=vulnerabilities)](https://sonarcloud.io/dashboard?id=asecurityteam_cisco-ise-log-parser-go)


## Adding new fields to the message parser

For certain types, this can be a one or two line change. If the field you want to parse is in the retrieveParseFn switch, simply add it to the LogMessage struct. The parser will parse with the existing generic parse function. If the field has a name that won't be auto-formatted to the Upper-camel-case style by the formatKey function, map the JSON field name from the message CSV to the correctly formatted struct field name.

If your field requires more complicated parsing, you will need to write a parse function that meets the valueParseFn definition, and then map the JSON field name to your custom parse function in the keyValueParseFuncMap. You can see examples of how to this by looking at the parseCiscoAVPair function.

If you don't plan on forking this repo, you can find any field not included in the existing LogMessage struct in the UnexpectedFields map in the MessageDetails field. The key will be the JSON field name found in the message CSV.
