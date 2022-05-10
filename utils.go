package bip32

import (
	"bytes"
	"errors"
	"math/big"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"

	"golang.org/x/crypto/ripemd160"
)

var (
	hardenedPubKeyError = errors.New("Error: not possible to create a hardened child key from a public key")

	invalidMasterKey = errors.New("Invalid master key: key should be between 1 and n-1")
	invalidChildKey = errors.New("Invalid child key: out of range")
	notPrivKeyError = errors.New("Invalid private key: key must be private")
	notPubKeyError = errors.New("Invalid public key: key must be public")
	invalidChecksumError = errors.New("Invalid key: checksum is not valid")

	invalidPrivKeyPrefix = errors.New("Invalid key: invalid private key prefix (should be 0x00)")
	invalidPrivKeyRange = errors.New("Invalid key: private key should be between 1 and n-1")
	invalidPubKeyPrefix = errors.New("Invalid key: invalid public key prefix (should be 0x02 or 0x03)")
	invalidPubKeyPoint = errors.New("Invalid key: public key should be a point in the secp256k1 curve")
	invalidPubKeySqrt = errors.New("Invalid key: x coordinate is not a square mod p")
	invalidKeyVersion = errors.New("Invalid key: version field is not valid")
	invalidKeyDepth = errors.New("Invalid key: mismatch between depth field (master key) and non-zero fingerprint / index")
	invalidKeySize = errors.New("Invalid key: serialized key must have 82 bytes")
	
)

/************************** Hashing functions *****************************/
// getHmac512 returns the HMAC-SHA512 of a given input and key
func getHmac512(input []byte, key []byte) []byte {
	hmac512 := hmac.New(sha512.New, key)
	hmac512.Write(input)
	return hmac512.Sum(nil)
}

// getSha256 returns the SHA256 of a given input
func getSha256(input []byte) []byte{
	sha256 := sha256.New()
	sha256.Write(input)
	return sha256.Sum(nil)
}

// getRipemd160 returns the RIPEMD160 of a given input
func getRipemd160(input []byte) []byte{
	ripemd160 := ripemd160.New()
	ripemd160.Write(input)	
	return ripemd160.Sum(nil)
}

// getHash160 returns the RIPEMD160(SHA256) of a given input
func getHash160(input []byte) []byte{
	return getRipemd160(getSha256(input))
}

// getDoubleSha256 returns the double SHA256 of a given input
func getDoubleSha256(input []byte) []byte {
	return getSha256(getSha256(input))
}

// getDoubleSha256 returns the fingerprint (first 4 bytes of the hash 160) 
// of a given input
func getFingerprint(input []byte) []byte{
	identifier := getHash160(input)
	return identifier[:4]
}


// addChecksum appends the double SHA256 checksum (first 4 bytes) of a
// given input
func addChecksum(input []byte) []byte {
	checksum := getDoubleSha256(input)
	output := append(input, checksum[:4]...)
	return output
}


/************************** Check Valid Key functions *****************************/
// checkValidMasterKey checks if the generated master key is valid
func checkValidMasterKey(masterKey []byte) error {
	if bytes.Compare(masterKey,curve256.N.Bytes())>=0 || bytes.Compare(masterKey,zeroPrivKey)==0 {
		return invalidMasterKey
	}
	return nil
}

// checkValidChildKey checks if the generated child key is valid 
func checkValidChildKey(hmacLeft []byte, childKey []byte) error {
	if bytes.Compare(hmacLeft,curve256.N.Bytes())>=0 || bytes.Compare(childKey,zeroPrivKey)==0 {
		return invalidChildKey
	}
	return nil
}

// checkPrivKey checks if the provided key is private 
func checkPrivKey(key *extKey) error {
	if bytes.Compare(key.Version, privWalletVersion)!=0 {
		return notPrivKeyError
	}
	return nil
}

// checkPubKey checks if the provided key is public 
func checkPubKey(key *extKey) error {
	if bytes.Compare(key.Version, pubWalletVersion)!=0 {
		return notPubKeyError
	}
	return nil
}

// checkValidChecksum checks if the checksum og a given input is valid
func checkValidChecksum(input []byte, checksum []byte) error {
	newChecksum := getDoubleSha256(input)
	if bytes.Compare(newChecksum[:4], checksum)!=0 {
		return invalidChecksumError
	}
	return nil
}

// checkValidChecksum checks if the extended key is valid
func checkValidExtKey(key *extKey) error {
	// if key is private
	if bytes.Compare(key.Version, privWalletVersion)==0 {
		// we check for the 0x00 prefix
		if key.Key[0]!=0 {
			return invalidPrivKeyPrefix	// invalid private key prefix
		}
		// we check if the private key is a valid number
		if bytes.Compare(key.Key[1:],curve256.N.Bytes())>=0 || bytes.Compare(key.Key[1:],zeroPrivKey)==0 {
			return invalidPrivKeyRange // invalid private key
		}
	// if key is public
	} else if bytes.Compare(key.Version, pubWalletVersion)==0 {
		// we check for the 0x02 / 0x03 prefix
		if (key.Key[0]!=2 && key.Key[0]!=3){
			return invalidPubKeyPrefix	// invalid public key prefix
		}
		// we uncompress the key and check if the point is on the secp256k1 curve
		x,y,err := uncompressPubKey(key.Key)
		if err!=nil {
			return err
		}
		if !curve256.IsOnCurve(x,y) {
			return invalidPubKeyPoint	// invalid public key
		}
	} else {
		return invalidKeyVersion	// invalid version
	}
	// if master key, we check for non-zero fingerprint / child index
	if key.Depth==0 && (bytes.Compare(key.Fingerprint, []byte{0, 0, 0, 0})!=0 || bytes.Compare(key.ChildNumber, []byte{0, 0, 0, 0})!=0) {
		return invalidKeyDepth		// invalid depth
	}

	return nil
}


/************************** Key calculation functions  *****************************/
// sumPrivKeys returns the sum of two private keys
func sumPrivKeys(firstKey []byte, secondKey []byte) []byte{
	firstInt := new(big.Int).SetBytes(firstKey)		 
	secondInt := new(big.Int).SetBytes(secondKey)	 	// we remove the 0x00 prefix from the private key
	firstInt.Add(firstInt, secondInt)			
	firstInt.Mod(firstInt, curve256.N)
	outKey := leftZeroPad(firstInt.Bytes(), 32)
	return outKey
}

// sumPrivKeys returns the sum of two public keys
func sumPubKeys(firstKey []byte, secondKey []byte) ([]byte, error) {
	x1, y1, err := uncompressPubKey(firstKey)	// we uncompress the first key
	if err!=nil {
		return nil, err
	}
	x2, y2, err := uncompressPubKey(secondKey)	// we uncompress the second key
	if err!=nil {
		return nil, err
	}
	x, y := curve256.Add(x1,y1,x2,y2)
	outKey := compressPubKey(x,y)
	return outKey, nil
}

// ellipticCurvePointMult returns the coordinate pair resulting from the elliptic curve
// point multiplication secp256k1 base point with the input byte slice
func ellipticCurvePointMult(input []byte) (*big.Int, *big.Int){
	x, y := curve256.ScalarBaseMult(input)
	return x, y
}

// getCompressedPubKey returns the compressed public key of a given extended private 
// key in the form of a 33-byte slice (includes the 0x02 or 0x03 prefix)
func getCompressedPubKey(key []byte) []byte {
	x, y := ellipticCurvePointMult(key)
	return compressPubKey(x,y)
}

// compressPubKey returns the compressed version of a public key given the coordinate
// pair (with the 0x02 or 0x03 prefix)
func compressPubKey(x *big.Int, y *big.Int) []byte {
	var publicKey []byte
	if y.Bit(0)==0 {
		publicKey = append([]byte{2}, x.Bytes()...)		
	} else {
		publicKey = append([]byte{3}, x.Bytes()...)
	}
	return publicKey
}

// uncompressPubKey returns the coordinate pair of a compressed public key 
func uncompressPubKey(key []byte) (*big.Int, *big.Int, error) {
	x := new(big.Int).SetBytes(key[1:])		// we take the x coordinate (without the prefix)
	y := big.NewInt(0)
	
	// we compute y^2=x^3+b
	y.Exp(x, big.NewInt(3), nil)
	y.Add(y, curve256.B)
	y.ModSqrt(y, curve256.P)
	if y==nil{
		return nil, nil, invalidPubKeySqrt	// invalid x coordinate
	}

	// we change the sign of if necessary
	if y.Bit(0)!=uint(key[0]) & 1 {
		y.Neg(y)
		y.Mod(y, curve256.P)
	}

	return x, y, nil
}



/************************** Other functions *****************************/
// leftZeroPad zero pads a byte slice to a targer size
func leftZeroPad(inputBytes []byte, targetSize int) []byte{
	offset := targetSize - len(inputBytes)
	paddedBytes := make([]byte, targetSize)
	copy(paddedBytes[offset:], inputBytes)
	return paddedBytes
}