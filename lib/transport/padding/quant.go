package padding

/** Quant is to be used for hybrid padding schemes where the padding is a mix of random
 * and fixed padding. This allows for a more flexible padding scheme that can adapt to different
 * message sizes while still providing a predictable level of security.
 *
 * Example Quantum+Random Padding Schemed:
 * - 16 byte limit = QuantAdjustment(messageSize, 4) + Random(0, 12)
 * - 32 byte limit = QuantAdjustment(messageSize, 8) + Random(0, 24)
 * - 48 byte limit = QuantAdjustment(messageSize, 16) + Random(0, 32)
 * - 64 byte limit = QuantAdjustment(messageSize, 16) + Random(0, 48)
 *
 * Why use Quantized padding?
 * - Quantized padding forced messages of similar sizes into the same quantum.
 * - This makes the messages within the same quantum indistinguishable from eachother.
 * - However, it also narrows the class of messages that can exist within a quantum.
 * - SO, the padding is a mix of random and fixed padding, which first buckets the messages by padding them to the same quantum
 * - Then adding a random amount of padding greater than the quantum.
 * - 8 and 16 byte quantums have specific alignment advantages, 32 bytes of padding in the scheme above results in most small messages being uncategorizable by size.
 * - 16 byte quantum with 48 bytes of padding is sufficient to make almost all small messages uncategorizable by size.
 *
 * Math to be published elsewhere, later.
 */

// Quant returns the next multiple of quantum that is greater than or equal to input.
// For example, Quant(10, 8) returns 16, as 16 is the next multiple of 8 that's >= 10.
func Quant(input, quantum int) int {
	// Handle edge cases
	if quantum <= 0 {
		panic("quantum must be positive")
	}

	// If input is already a multiple of quantum, return input
	if input%quantum == 0 {
		return input
	}

	// Calculate the next multiple of quantum
	// This is equivalent to: ceil(input/quantum) * quantum
	return ((input / quantum) + 1) * quantum
}

// QuantAdujustment returns the amount of padding needed to make the input a multiple of quantum.
// For example, if input is 10 and quantum is 8, the adjustment would be 6 (to reach 16).
func QuantAdjustment(input, quantum int) int {
	// Handle edge cases
	if quantum <= 0 {
		panic("quantum must be positive")
	}

	// Calculate the next multiple of quantum
	nextMultiple := Quant(input, quantum)

	// Return the difference between the next multiple and the input
	return nextMultiple - input
}
