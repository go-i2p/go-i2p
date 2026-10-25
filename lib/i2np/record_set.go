package i2np

// sliceRecordSet backs the slice-typed tunnel build message (ShortTunnelBuild).
// It stores the records as a []BuildRequestRecord with an accompanying Count.
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
