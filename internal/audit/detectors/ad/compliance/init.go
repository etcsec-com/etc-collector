// Package compliance imports all compliance-related detectors
package compliance

import (
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/compliance/anssi"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/compliance/cis"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/compliance/disa"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/compliance/industry"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/compliance/nist"
)
