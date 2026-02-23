package unobpx

// ComputeOBXORKey derives the OB XOR decryption key from a PX tag string.
//
// This replicates init.js function Gf():
//
//	e = (31 * e + charCode) % 2147483647   for each character
//	key = ((e % 900) + 100) % 128
//
// The tag string is visible in the init.js source and is also sent as
// the "tag" POST parameter in every sensor request.
func ComputeOBXORKey(tag string) byte {
	var e int64
	for _, ch := range tag {
		e = (31*e + int64(ch)) % 2147483647
	}
	return byte(((e % 900) + 100) % 128)
}
