# __bip32__
## Introduction
This package is an implementation of the __[BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)__ specifications in the __[Go programming language](https://go.dev/)__. You can read the documentation __[here](https://pkg.go.dev/github.com/augcos/bip32)__.

## Example
```go
package main

import (
    "fmt"

    "github.com/augcos/bip32"
    "github.com/augcos/bip39"
)

func main() {
    // we generate the random entropy
    entropy, _ := bip39.GenEntropy(256)
    // we generate the mnemonic corresponding to that entropy
    mnemonic, _ := bip39.GetMnemonicFromEntropy(entropy)
    // finally, we generate the 512-bit seed from the mnemonic, plus a passphrase
    seed, _ := bip39.GetSeedFromMnemonic(mnemonic, "passphrase")

    // we create the master key
    masterKey, _ := bip32.GenMasterKey(seed)
    // we derivate the child private key
    childKey, _ := bip32.ChildKeyDeriv(masterKey, 0)
    // we get the child public key from the private key
    pubChildKey, _ := bip32.Neuter(childKey)

    // we serialize the child public key
    serializedPubChildKey, _ := bip32.Serialization(pubChildKey)

    fmt.Println("Public Child Key:", serializedPubMasterKey)
}
```

## References
* [__BIP32 specifications__](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
* [__Mastering Bitcoin__](https://github.com/bitcoinbook/bitcoinbook) by Andreas M. Antonopoulos: 
* Tyler Smith's __[BIP32 Go implementation](https://github.com/tyler-smith/go-bip32)__