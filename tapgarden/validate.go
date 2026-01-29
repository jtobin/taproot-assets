package tapgarden

// ValidateSeedling performs stateless validation on a seedling's fields.
// This is a wrapper around the internal validateFields method for use in
// testing and external validation.
//
// Note: This function does not validate the group key. Group key validation
// requires database access to verify key ownership and is performed
// separately during the minting flow.
//
// Also note: Collectible assets have their amounts silently corrected to 1
// during batch sealing for backward compatibility. This validation does not
// enforce the amount=1 constraint for collectibles.
func ValidateSeedling(s *Seedling) error {
	return s.validateFields()
}
