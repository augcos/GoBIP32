package bip32

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"

	"github.com/btcsuite/btcutil/base58"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)


/************************** Extended Key Struct *****************************/
type extKey struct {
	Version			[]byte
	Depth			byte
	Fingerprint		[]byte
	ChildNumber		[]byte
	ChainCode		[]byte
	Key				[]byte
}


/************************** Internal package variables *****************************/
var (
	curve256 = secp256k1.S256()
	zeroPrivKey = make([]byte, 32)
	privWalletVersion, _ = hex.DecodeString("0488ADE4")
	pubWalletVersion, _ = hex.DecodeString("0488B21E")
	limitHardened = uint32(0x80000000)
)

/************************** Master Key Generation *****************************/
// GenMasterKey takes a seed as an input and returns a Key object for the master
// key
func GenMasterKey(seed []byte) (*extKey, error){
	// we get the HMAC-512 of the seed
	hmac := getHmac512(seed, []byte("Bitcoin seed"))
	key := hmac[:32] 
	chainCode := hmac[32:] 

	// we check that the private key is valid
	err := checkValidMasterKey(key)
	if err!=nil {
		return nil, err		
	}

	// the master key is saved as a pointer to a Key struct
	masterKey := &extKey {
		Version:		privWalletVersion,
		Depth:			0,
		Fingerprint:	[]byte{0, 0, 0, 0},
		ChildNumber: 	[]byte{0, 0, 0, 0},
		ChainCode:		chainCode,
		Key: 			append([]byte{0}, key...),
	}

	return masterKey, nil
}



/************************** Child Key Derivation *****************************/
// ChildKeyGenPriv returns a Key object with a private child key using as input
// its parent key and a child index (capable of producing both hardened and
// non-hardened keys)
func ChildKeyDerivPriv(parentKey *extKey, index uint32) (*extKey, error) {
	// we check that the parent is a private key
	if err:=checkPrivKey(parentKey); err!=nil {
		return nil, err
	}
	
	// we get the child index as a []byte
	childIndex := make([]byte, 4)
	binary.BigEndian.PutUint32(childIndex, index)
	// we compute the parent public key
	pubParentKey := getCompressedPubKey(parentKey.Key[1:])

	// we create the input for the HMAC-SHA512 appending the child index
	// as a sufix
	var hmacInput []byte
	if index>=limitHardened {
		// for hardened keys we use the parent private key 
		hmacInput = append(parentKey.Key, childIndex...)
	} else {
		// for non-hardened keys we use the parent public key 
		hmacInput = append(pubParentKey, childIndex...)
	}
	
	// we get the HMAC-SHA512 of the input, the right bits will be used
	// as the chaincode
	hmac := getHmac512(hmacInput, parentKey.ChainCode)
	hmacKey := hmac[:32]
	chainCode := hmac[32:]
	

	// we get the child private key from the left bits of the HMAC-SHA512
	// output and the parent private key
	childPrivKey := sumPrivKeys(hmacKey, parentKey.Key[1:])
	// we check that the child key is valid
	if err:= checkValidChildKey(hmacKey, childPrivKey); err!=nil {
		return nil, err
	}

	// we compute the child fingerprint
	childFingerprint := getFingerprint(pubParentKey)
	// we create a new Key object for the child key
	childKeyObj := &extKey {
		Version:		privWalletVersion,
		Depth:			parentKey.Depth + 1,
		Fingerprint:	childFingerprint,
		ChildNumber: 	childIndex,
		ChainCode:		chainCode,
		Key: 			append([]byte{0}, childPrivKey...),
	}

	return childKeyObj, nil
}


// ChildKeyGenPub returns a Key object with a private child key using as input
// its parent key and a child index (capable of producing both hardened and
// non-hardened keys)
func ChildKeyDerivPub(parentKey *extKey, index uint32) (*extKey, error) {
	// we check that the parent is a public key
	if err:=checkPubKey(parentKey); err!=nil {
		return nil, err
	}
	// we check that the child is not a hardened key
	if index>=limitHardened {
		return nil, hardenedPubKeyError
	}

	// we get the child index as a []byte
	childIndex := make([]byte, 4)
	binary.BigEndian.PutUint32(childIndex, index)

	// we create the input for the HMAC-SHA512 appending the child index
	// as a sufix to the parent public key
	hmacInput := append(parentKey.Key, childIndex...)

	// we get the HMAC-SHA512 of the input, the right bits will be used
	// as the chaincode
	hmac := getHmac512(hmacInput, parentKey.ChainCode)
	hmacKey := hmac[:32]
	chainCode := hmac[32:]

	// we get the child private key from the left bits of the HMAC-SHA512
	// output and the parent private key
	pubHmacKey := getCompressedPubKey(hmacKey)
	childPubKey, err := sumPubKeys(pubHmacKey, parentKey.Key)
	if err!=nil {
		return nil, err
	}

	// we check that the child key is valid
	if err:= checkValidChildKey(hmacKey, childPubKey); err!=nil {
		return nil, err
	}

	// we compute the child fingerprint
	childFingerprint := getFingerprint(parentKey.Key)

	// we create a new Key object for the child key
	childKeyObj := &extKey {
		Version:		pubWalletVersion,
		Depth:			parentKey.Depth + 1,
		Fingerprint:	childFingerprint,
		ChildNumber: 	childIndex,
		ChainCode:		chainCode,
		Key: 			childPubKey,
	}

	return childKeyObj, nil
}


/************************** Neuter function *****************************/
// Neuter returns the extended public key corresponding to a given extended
// private key
func Neuter(parentKey *extKey) (*extKey, error){
	// we check that the parent is a private key
	if bytes.Compare(parentKey.Version, privWalletVersion)!=0 {
		return nil, notPrivKeyError
	}

	// we compute the parent public key
	pubKey := getCompressedPubKey(parentKey.Key[1:])

	// we create a new Key object for the public key
	pubKeyObj := &extKey {
		Version:		pubWalletVersion,
		Depth:			parentKey.Depth,
		Fingerprint:	parentKey.Fingerprint,
		ChildNumber: 	parentKey.ChildNumber,
		ChainCode:		parentKey.ChainCode,
		Key: 			pubKey,
	}

	return pubKeyObj, nil
}


/************************** Serialization functions  *****************************/
// getUncompressedPubKey returns the uncompressed public key of a given private key in
// the form of a 64-byte slice (does not include 0x04 prefix)
func Serialization(key *extKey) (string, error) {
	byteBuffer := new(bytes.Buffer)
	byteBuffer.Write(key.Version)
	byteBuffer.WriteByte(key.Depth)
	byteBuffer.Write(key.Fingerprint)
	byteBuffer.Write(key.ChildNumber)
	byteBuffer.Write(key.ChainCode)
	byteBuffer.Write(key.Key)
	keyBytes := addChecksum(byteBuffer.Bytes())
	
	return base58.Encode(keyBytes), nil
}

// getCompressedPubKey returns the compressed public key of a given private key in the 
// form of a 33-byte slice (includes the 0x02 or 0x03 prefix)
func Deserialization(serializedKey string) (*extKey, error) {
	keyBytes := base58.Decode(serializedKey)
	if err:=checkValidChecksum(keyBytes[:78], keyBytes[78:]); err!=nil {
		return nil, err
	}
	key := &extKey {
		Version:		keyBytes[0:4],
		Depth:			keyBytes[4],
		Fingerprint:	keyBytes[5:9],
		ChildNumber: 	keyBytes[9:13],
		ChainCode:		keyBytes[13:45],
		Key: 			keyBytes[45:78],
	}

	return key, nil
}