package bip32

import (
	"bytes"
	"errors"
	"binary"
	"math/big"
	"crypto/rand"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"

	"golang.org/x/crypto/ripemd160"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

var (
	invalidPrivKeyError = errors.New("Invalid private key: must be larger than 0 and smaller than the order of the secp256k1 curve")
	readerHmacError = errors.New("Error reading the bits from the HMAC function")
	hardenedPubKeyError = errors.New("Not possible to create hardened child key from a public key")
	notPrivKeyError = errors.New("Key must be private in order to get the public key")
	privKeyError = errors.New("Key is private: must be public")
	invalidChecksumError = errors.New("Checksum is not valid")
)

/************************** Hashing functions *****************************/
func getHmac512(input []byte) []byte {
	hmac512 := hmac.New(sha512.New, []byte("Bitcoin seed"))
	hmac512.Write(input)
	return hmac512.Sum(nil)
}

func getSha256(input []byte) []byte{
	sha256 := sha256.New()
	sha256.Write(key)
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
	output := append(input, checksum...)
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
	if bytes.Compare(newChecksum, checksum)!=0 {
		return invalidChecksumError
	}
	return nil
}


/************************** Key calculation functions  *****************************/
func sumPrivKeys(firstKey []byte, secondKey []byte) []byte{
	firstInt := new(big.Int).SetBytes(sumPrivKeys)		 
	secondInt := new(big.Int).SetBytes(secondKey)	 	// we remove the 0x00 prefix from the private key
	firstInt.Add(firstInt, secondInt)					
	firstInt.Mod(firstInt, curve256.N)
	outKey := leftZeroPad(firstInt.Bytes(), 32)
	return outKey, nil
}

func sumPubKeys(firstKey []byte, secondKey []byte) []byte {
	x1, y1 := curve256.Unmarshal(firstKey)
	x2, y2 := curve256.Unmarshal(secondKey)
	x, y := curve256.Add(x1,y1,x2,y2)
	outKey := curve256.Marshal(x,y)
	return outKey
}

// ellipticCurvePointMult returns the coordinate pair resulting from the elliptic curve
// point multiplication secp256k1 base point with the input byte slice
func ellipticCurvePointMult(input []byte) (*big.Int, *big.Int){
	x, y := curve256.ScalarBaseMult(input)
	return x, y
}

// getUncompressedPubKey returns the uncompressed public key of a given extended private
// key in the form of a 64-byte slice (does not include 0x04 prefix)
func getUncompressedPubKey(key []byte) []byte {
	x, y := ellipticCurvePointMult(key)
	publicKey = append(x.Bytes(), y.Bytes()...)			// we concatenate the coordinate pair bits
	return publicKey, nil
}

// getCompressedPubKey returns the compressed public key of a given extended private 
// key in the form of a 33-byte slice (includes the 0x02 or 0x03 prefix)
func getCompressedPubKey(key []byte) []byte {
	x, y := ellipticCurvePointMult(key)
	publicKey := curve256.Marshal(x,y)		// we get the compressed public key
	return publicKey, nil
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





/************************** Other functions *****************************/
// leftZeroPad zero pads a byte slice to a targer size
func leftZeroPad(inputBytes []byte, byteSize int) []byte{
	offset := targetSize - len(inputBytes)
	paddedBytes := make([]byte, byteSize)
	copy(paddedBytes[offset:], inputBytes)
	return paddedBytes
}