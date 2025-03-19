package padding

type PaddingStrategy interface {
	AddPadding(message []byte) []byte
	RemovePadding(message []byte) []byte
}

type NullPaddingStrategy struct{}

func (p *NullPaddingStrategy) AddPadding(message []byte) []byte {
	return message
}

func (p *NullPaddingStrategy) RemovePadding(message []byte) []byte {
	return message
}
