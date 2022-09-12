package base32

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncodeDecodeNotMangled(t *testing.T) {
	assert := assert.New(t)

	// Random pangram
	testInput := []byte("How vexingly quick daft zebras jump!")

	encodedString := EncodeToString(testInput)
	decodedString, err := DecodeString(encodedString)
	assert.Nil(err)

	assert.ElementsMatch(testInput, decodedString)
}
