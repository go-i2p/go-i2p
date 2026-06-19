package i2np

// sliceRecordSet is a shared embedding for slice-backed tunnel build types
// (VariableTunnelBuild and ShortTunnelBuild).  Both types store their records
// as a []BuildRequestRecord with an accompanying Count; the accessor logic is
// identical, so a single embedded helper eliminates the duplication.
//
// TunnelBuild (fixed [8]array) is intentionally not handled here because its
// backing storage and constant count differ in a way that does not benefit from
// the same embedding.
type sliceRecordSet struct {
	Count               int
	BuildRequestRecords []BuildRequestRecord
}

// GetBuildRecords returns the build request records.
func (s *sliceRecordSet) GetBuildRecords() []BuildRequestRecord {
	return s.BuildRequestRecords
}

// GetRecordCount returns the number of build records.
func (s *sliceRecordSet) GetRecordCount() int {
	return s.Count
}
