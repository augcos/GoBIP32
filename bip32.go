package main

import (
	"fmt"
	"bytes"
	"errors"
	"binary"
	"math/big"
	"crypto/rand"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

func main() {
	fmt.Println("Development...")
	entropy := make([]byte, 32)
	rand.Read(entropy)
	a,_ := GetMasterKey(entropy)
	_,_ = NewChildKey(a,1)
	//fmt.Println(curve256.N.Bytes())
}



/************************** Package variables *****************************/
var (
	curve256 = secp256k1.S256()
	zeroPrivKey = make([]byte, 32)

	invalidPrivKeyError = errors.New("Invalid private key: must be larger than 0 and smaller than the order of the secp256k1 curve")
	readerHmacError = errors.New("Error reading the bits from the HMAC function")
	hardenedPubKeyError = errors.New("Not possible to create hardened child key from a public key")
	notPrivKeyError = errors.New("Key must be private in order to get the public key")

	privWalletVersion, _ = hex.DecodeString("0488ADE4")
	pubWalletVersion, _ = hex.DecodeString("0x0488B21E")
	limitHardened = uint32(0x80000000)
)



/************************** Structs *****************************/
type Key struct {
	Version			[]byte
	Depth			byte
	FingerPrint		[]byte
	ChildNumber		[]byte
	ChainCode		[]byte
	Key				[]byte
	IsExtended		bool
	IsPrivate		bool
}




/************************** Main Functions *****************************/
// GetMasterKey 
func GetMasterKey(seed []byte) (*Key, error){
	// we get the HMAC-512 of the seed
	privateKey, chainCode, err := getHmac512(seed)
	if err!=nil {
		return nil, err		
	}

	// we check that the private key is valid
	err = checkValidPrivateKey(privateKey)
	if err!=nil {
		return nil, err		
	}

	// the private key is saved as a pointer to a Key struct
	masterKey := &Key {
		Version:		privWalletVersion,
		Depth:			0,
		FingerPrint:	[]byte{0, 0, 0, 0},
		ChildNumber: 	[]byte{0, 0, 0, 0},
		ChainCode:		chainCode,
		Key: 			append([]byte{0}, privateKey...),
		IsExtended:		true,
		IsPrivate:		true,
	}

	return masterKey, nil
}





func NewChildKey(parentKey *Key, index uint32) (*Key, error){	
	// if the child key is hardened and the parent key is not private
	// we return an error
	if index>limitHardened && !parentKey.IsPrivate {
		return nil, hardenedPubKeyError
	}

	// if the child key is hardened and the parent key is not private
	// we return an error
	var input []byte
	if index>limitHardened || !parentKey.IsPrivate {
		input = parentKey.Key
	} else {
		input, err = getPublicKey(parentKey.Key)
		if err!=nil {
			return nil, err
		}
	}

	//
	childIndex := make([]byte, 4)
	binary.BigEndian.PutUint32(childIndex, index)
	hmacInput = append(input, childIndex...)

	//
	childKey, chainCode, err := getHmac512(hmacInput)
	if err!=nil {
		return nil, err		
	}

	//
	newChildKey := &Key {
		Depth:			parentKey.Depth + 1,
		ChildNumber: 	childIndex,
		ChainCode:		chainCode,
		IsPrivate:		parentKey.IsPrivate,
	}

	//
	if parentKey.IsPrivate {
		newChildKey.Version = privWalletVersion
		parentPubKey, err := getPublicKey(parentKey.Key)
		if err!=nil {
			return nil, err
		}
	} else {

	}

	return newChildKey, nil
}





/************************** Utilities *****************************/
// getHmac512
func getHmac512(input []byte) ([]byte, []byte, error) {
	// we get the HMAC-512 of the seed
	hmac512 := hmac.New(sha512.New, []byte("Bitcoin seed"))
	_, err := hmac512.Write(input)
	if err!=nil{
		return nil, nil, readerHmacError
	}
	
	// the HMAC-512 is separated into private key and chaincode
	hash := hmac512.Sum(nil)
	newKey := hash[:32]
	chainCode := hash[32:]

	return newKey, chainCode, nil
}


// checkValidPrivateKey checks if the generated private master key 
// is valid and returns the corresponding err
func checkValidPrivateKey(privateKey []byte) error {
	if (bytes.Compare(privateKey,zeroPrivKey)==0) || (bytes.Compare(privateKey,curve256.N.Bytes())>=0) {
		return invalidPrivKeyError
	}
	return nil
}


func getPublicKey(privateKey *Key) ([]byte, error) {
	if !privateKey.IsPrivate {
		return nil, notPrivKeyError
	}
	x, y := curve256.ScalarBaseMult(privateKey.Key[1:])
	publicKey := compressPubKey(x,y)
	return publicKey, nil
}


func compressPubKey(x *big.Int, y *big.Int) []byte {
	var publicKey []byte
	if y.Bit(0)==0 {
		publicKey = append([]byte{2}, x.Bytes()...)		
	} else {
		publicKey = append([]byte{3}, x.Bytes()...)
	}
	return publicKey
}
