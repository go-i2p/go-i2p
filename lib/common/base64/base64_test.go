package base64

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncodeDecodeNotMangled(t *testing.T) {
	assert := assert.New(t)

	// Random pangram
	testInput := []byte("Glib jocks quiz nymph to vex dwarf.")

	encodedString := EncodeToString(testInput)
	decodedString, err := DecodeString(encodedString)
	assert.Nil(err)

	assert.ElementsMatch(testInput, decodedString)
}
