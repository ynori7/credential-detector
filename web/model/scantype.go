package model

import "github.com/ynori7/credential-detector/config"

// AllScanTypes lists every supported scan type in display order.
var AllScanTypes = []string{
	config.ScanTypeGo,
	config.ScanTypeYaml,
	config.ScanTypeJSON,
	config.ScanTypeProperties,
	config.ScanTypePrivateKey,
	config.ScanTypeXML,
	config.ScanTypePHP,
	config.ScanTypeBash,
	config.ScanTypeJavaScript,
	config.ScanTypeHTML,
	config.ScanTypeGeneric,
	config.ScanTypeGenericCode,
}
