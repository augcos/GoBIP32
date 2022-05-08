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
	invalidPrivKeyError = errors.New("Invalid private key: must be larger than 0 and smaller than the order of the secp256k1 curve")
	readerHmacError = errors.New("Error reading the bits from the HMAC function")
	hardenedPubKeyError = errors.New("Not possible to create hardened child key from a public key")
	notPrivKeyError = errors.New("Key must be private in order to get the public key")
	privKeyError = errors.New("Key is private: must be public")
	invalidChecksumError = errors.New("Checksum is not valid")
	invalidKeyEcdsa = errors.New("Invalid key: does not correspond to any point in the secp256k1 curve")
)

/************************** Hashing functions *****************************/
func getHmac512(input []byte, key []byte) []byte {
	hmac512 := hmac.New(sha512.New, key)
	hmac512.Write(input)
	return hmac512.Sum(nil)
}

func getSha256(input []byte) []byte{
	sha256 := sha256.New()
	sha256.Write(input)
	return sha256.Sum(nil)
}

func getRipemd160(input []byte) []byte{
	ripemd160 := ripemd160.New()
	ripemd160.Write(input)	
	return ripemd160.Sum(nil)
}

func getHash160(input []byte) []byte{
	return getRipemd160(getSha256(input))
}

func getDoubleSha256(input []byte) []byte {
	return getSha256(getSha256(input))
}

func getFingerprint(input []byte) []byte{
	identifier := getHash160(input)
	return identifier[:4]
}

func addChecksum(input []byte) []byte {
	checksum := getDoubleSha256(input)
	output := append(input, checksum[:4]...)
	return output
}


/************************** Check Valid Key functions *****************************/
// checkValidPrivateKey checks if the generated master key is valid
func checkValidMasterKey(masterKey []byte) error {
	if bytes.Compare(masterKey,curve256.N.Bytes())>=0 || bytes.Compare(masterKey,zeroPrivKey)==0 {
		return invalidPrivKeyError
	}
	return nil
}

// checkValidChildKey checks if the generated child key is valid 
func checkValidChildKey(hmacLeft []byte, childKey []byte) error {
	if bytes.Compare(hmacLeft,curve256.N.Bytes())>=0 || bytes.Compare(childKey,zeroPrivKey)==0 {
		return invalidPrivKeyError
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

// checkPrivKey checks if the provided key is private 
func checkPubKey(key *extKey) error {
	if bytes.Compare(key.Version, pubWalletVersion)!=0 {
		return notPrivKeyError
	}
	return nil
}

// checkValidChecksum checks if the provided key is private 
func checkValidChecksum(input []byte, checksum []byte) error {
	newChecksum := getDoubleSha256(input)
	if bytes.Compare(newChecksum[:4], checksum)!=0 {
		return invalidChecksumError
	}
	return nil
}


/************************** Key calculation functions  *****************************/
func sumPrivKeys(firstKey []byte, secondKey []byte) []byte{
	firstInt := new(big.Int).SetBytes(firstKey)		 
	secondInt := new(big.Int).SetBytes(secondKey)	 	// we remove the 0x00 prefix from the private key
	firstInt.Add(firstInt, secondInt)			
	firstInt.Mod(firstInt, curve256.N)
	outKey := leftZeroPad(firstInt.Bytes(), 32)
	return outKey
}

func sumPubKeys(firstKey []byte, secondKey []byte) ([]byte, error) {
	x1, y1, err := uncompressPubKey(firstKey)
	if err!=nil {
		return nil, err
	}
	x2, y2, err := uncompressPubKey(secondKey)
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

func uncompressPubKey(key []byte) (*big.Int, *big.Int, error) {
	x := new(big.Int).SetBytes(key[1:])
	y := big.NewInt(0)
	
	y.Exp(x, big.NewInt(3), nil)
	y.Add(y, curve256.B)
	y.ModSqrt(y, curve256.P)
	if y==nil{
		return nil, nil, invalidKeyEcdsa
	}

	if y.Bit(0) !=  uint(key[0]) & 1 {
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