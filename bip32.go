package bip32

import (
	"bytes"
	"encoding/binary"

	"github.com/btcsuite/btcutil/base58"
)



/*********************************************** Extended Key Struct **************************************************/

// ExtKey is a struct type representing a extended key according to BIP32 specifications
type Extkey struct {
	Version			[]byte
	Depth			byte
	Fingerprint		[]byte
	ChildNumber		[]byte
	ChainCode		[]byte
	Key				[]byte
}



/********************************************** Master Key Generation *************************************************/

// GenMasterKey takes a seed as an input and returns the extended key for the master key
func GenMasterKey(seed []byte) (*Extkey, error){
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
	masterKey := &Extkey {
		Version:		privWalletVersion,
		Depth:			0,
		Fingerprint:	[]byte{0, 0, 0, 0},
		ChildNumber: 	[]byte{0, 0, 0, 0},
		ChainCode:		chainCode,
		Key: 			append([]byte{0}, key...),
	}

	return masterKey, nil
}



/*********************************************** Child Key Derivation *************************************************/

// ChildKeyDeriv is a generic interface for generating extended child keys from any exnteded parent keys, either private
// or public
func ChildKeyDeriv(parentKey *Extkey, index uint32) (*Extkey, error) {
	var childKey *Extkey
	var err error

	// we check if the key is private
	if bytes.Compare(parentKey.Version, privWalletVersion)==0 {
		childKey, err = ChildKeyDerivPriv(parentKey, index)
	// we check if the key is public
	} else if bytes.Compare(parentKey.Version, pubWalletVersion)==0 {
		childKey, err = ChildKeyDerivPub(parentKey, index)
	// otherwise, the key is invalid
	} else {
		return nil, invalidKeyVersion
	}
	return childKey, err
}


// ChildKeyGenPriv returns an extended private child key using as input its extended parent private key and a child
// index (capable of producing both hardened and non-hardened keys)
func ChildKeyDerivPriv(parentKey *Extkey, index uint32) (*Extkey, error) {
	// we check that the key is valid
	if err:=checkValidExtkey(parentKey); err!=nil {
		return nil, err
	}

	// we check that the parent is a private key
	if err:=checkPrivKey(parentKey); err!=nil {
		return nil, err
	}
	
	// we get the child index as a []byte
	childIndex := make([]byte, 4)
	binary.BigEndian.PutUint32(childIndex, index)
	// we compute the parent public key (compressed)
	pubParentKey := getCompressedPubKey(parentKey.Key[1:])

	// we create the input for the HMAC-SHA512 appending the child index as a sufix
	var hmacInput []byte
	if index>=limitHardened {
		// for hardened keys we use the parent private key 
		hmacInput = append(parentKey.Key, childIndex...)
	} else {
		// for non-hardened keys we use the parent public key 
		hmacInput = append(pubParentKey, childIndex...)
	}
	
	// we get the HMAC-SHA512 of the input, the right bits will be used as the chaincode
	hmac := getHmac512(hmacInput, parentKey.ChainCode)
	hmacKey := hmac[:32]
	chainCode := hmac[32:]
	
	// we get the child private key from the left bits of the HMAC-SHA512 output and the parent private key
	childPrivKey := sumPrivKeys(hmacKey, parentKey.Key[1:])
	// we check that the child key is valid
	if err:= checkValidChildKey(hmacKey, childPrivKey); err!=nil {
		return nil, err
	}

	// we compute the child fingerprint
	childFingerprint := getFingerprint(pubParentKey)
	// we create a new Key object for the child key
	childKeyObj := &Extkey {
		Version:		privWalletVersion,
		Depth:			parentKey.Depth + 1,
		Fingerprint:	childFingerprint,
		ChildNumber: 	childIndex,
		ChainCode:		chainCode,
		Key: 			append([]byte{0}, childPrivKey...),
	}

	return childKeyObj, nil
}


// ChildKeyGenPriv returns an extended public child key using as input its extended parent public key and a child index
func ChildKeyDerivPub(parentKey *Extkey, index uint32) (*Extkey, error) {
	// we check that the key is valid
	if err:=checkValidExtkey(parentKey); err!=nil {
		return nil, err
	}

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

	// we create the input for the HMAC-SHA512 appending the child index as a sufix to the parent public key
	hmacInput := append(parentKey.Key, childIndex...)

	// we get the HMAC-SHA512 of the input, the right bits will be used as the chaincode
	hmac := getHmac512(hmacInput, parentKey.ChainCode)
	hmacKey := hmac[:32]
	chainCode := hmac[32:]

	// we get the child private key from the left bits of the HMAC-SHA512 output and the parent private key
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
	childKeyObj := &Extkey {
		Version:		pubWalletVersion,
		Depth:			parentKey.Depth + 1,
		Fingerprint:	childFingerprint,
		ChildNumber: 	childIndex,
		ChainCode:		chainCode,
		Key: 			childPubKey,
	}

	return childKeyObj, nil
}


/************************************************* Neuter function ****************************************************/

// Neuter returns the extended public key corresponding to a given extended private key
func Neuter(privateKey *Extkey) (*Extkey, error){
	// we check that the key is valid
	if err:=checkValidExtkey(privateKey); err!=nil {
		return nil, err
	}

	// we check that the key is private
	if err:=checkPrivKey(privateKey); err!=nil {
		return nil, err
	}

	// we compute the parent public key
	pubKey := getCompressedPubKey(privateKey.Key[1:])

	// we create a new Key object for the public key
	pubKeyObj := &Extkey {
		Version:		pubWalletVersion,
		Depth:			privateKey.Depth,
		Fingerprint:	privateKey.Fingerprint,
		ChildNumber:	privateKey.ChildNumber,
		ChainCode:		privateKey.ChainCode,
		Key: 			pubKey,
	}

	return pubKeyObj, nil
}


/********************************************* Serialization functions  ***********************************************/

// Serialization returns the serialized extended key as a string
func Serialization(key *Extkey) (string, error) {
	// we check that the extended key is valid
	if err:=checkValidExtkey(key); err!=nil {
		return "", err
	}

	// we write the key fields to a byte buffer
	byteBuffer := new(bytes.Buffer)
	byteBuffer.Write(key.Version)
	byteBuffer.WriteByte(key.Depth)
	byteBuffer.Write(key.Fingerprint)
	byteBuffer.Write(key.ChildNumber)
	byteBuffer.Write(key.ChainCode)
	byteBuffer.Write(key.Key)

	// we append the checksum
	keyBytes := addChecksum(byteBuffer.Bytes())
	
	// we return the bytes encoded in Base58
	return base58.Encode(keyBytes), nil
}

// Deserialization returns the ExtKey objet of a given serialized key
func Deserialization(serializedKey string) (*Extkey, error) {
	// we decode the key from Base58
	keyBytes := base58.Decode(serializedKey)
	// we check if the byte length is correct
	if len(keyBytes)!=82 {
		return nil, invalidKeySize
	}
	// we check that the checksum is valid
	if err:=checkValidChecksum(keyBytes[:78], keyBytes[78:]); err!=nil {
		return nil, err
	}

	// we create the extended key object for the key
	key := &Extkey {
		Version:		keyBytes[0:4],
		Depth:			keyBytes[4],
		Fingerprint:	keyBytes[5:9],
		ChildNumber: 	keyBytes[9:13],
		ChainCode:		keyBytes[13:45],
		Key: 			keyBytes[45:78],
	}

	// we check that the extended key is valid
	if err:=checkValidExtkey(key); err!=nil {
		return nil, err
	}
	
	return key, nil
}