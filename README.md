# BIP32
## Introduction
This is an implementation of the [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) standard in the [Go programming language](https://go.dev/).
<br/></br>

## References
```
- BIP39 specifications: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
- Mastering Bitcoin by Andreas M. Antonopoulos: https://github.com/bitcoinbook/bitcoinbook
- Tyler Smith's BIP39 implementation: https://github.com/tyler-smith/go-bip32
```
<br/></br>

## Documentation
### type ExtKey
```
type ExtKey struct {
	Version         []byte
	Depth           byte
	Fingerprint     []byte
	ChildNumber     []byte
	ChainCode       []byte
	Key             []byte
}
```
An ExtKey object represents an extended key according to the BIP32 standard.

### func GenMasterKey
```
func GenMasterKey(seed []byte) (*ExtKey, error)
```
GenMasterKey takes a seed as an input and returns an extended key object for the master key.
<br/></br>

### func ChildKeyDeriv
```
func ChildKeyDeriv(parentKey *ExtKey, index uint32) (*ExtKey, error)
```
ChildKeyDeriv accepts any extended key (private or public), calls the corresponding child key derivation function and then returns the child key.
<br/></br>

### func ChildKeyDerivPriv
```
ChildKeyDerivPriv(parentKey *ExtKey, index uint32) (*ExtKey, error)
```
ChildKeyGenPriv returns an extended private child key using as input its extended parent private 
key and a child index (capable of producing both hardened and non-hardened keys).
<br/></br>

### func ChildKeyDerivPub
```
func ChildKeyDerivPub(parentKey *Extkey, index uint32) (*Extkey, error)
```
ChildKeyGenPriv returns an extended public child key using as input its extended parent public 
key and a child index.
<br/></br>

### func Neuter
```
func Neuter(privateKey *Extkey) (*Extkey, error)
```
Neuter returns the extended public key corresponding to a given extended private key.
<br/></br>

### func Serialization
```
func Serialization(key *Extkey) (string, error)
```
Serialization returns the serialized extended key as a string.
<br/></br>

### func Deserialization
```
func Deserialization(serializedKey string) (*Extkey, error)
```
// Deserialization returns the ExtKey objet of a given serialized key.