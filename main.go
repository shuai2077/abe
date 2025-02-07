package main

import (
	"encoding/json"
	"fmt"
	policy "github.com/fentec-project/gofe/abe"
)

func main() {
	inst := NewABE(256)
	instJson, _ := json.Marshal(inst)
	gamma := []string{"清华", "计算机"}

	//Setup
	var new_inst ABE
	err := json.Unmarshal(instJson, &new_inst)
	if err != nil {
		return
	}
	pubkey, seckey, err := new_inst.Setup(gamma)
	if err != nil {
		fmt.Println("Setup error:", err)
		return
	}
	pubKeyJson, err := json.Marshal(pubkey)
	secKeyJson, err := json.Marshal(seckey)
	var newPubkey ABEPubkey
	err = json.Unmarshal(pubKeyJson, &newPubkey)
	var newSeckey ABESeckey
	err = json.Unmarshal(secKeyJson, &newSeckey)

	//Key Generation
	attribKeys, err := new_inst.KeyGen(gamma, &newPubkey, &newSeckey)
	if err != nil {
		fmt.Println("KeyGen error:", err)
		return
	}
	attribkeysJson, err := json.Marshal(attribKeys)
	var newattribKeys ABEAttribKeys
	err = json.Unmarshal(attribkeysJson, &newattribKeys)
	if err != nil {
		return
	}

	//Encrypt
	msg := "Hello, ABE encryption!!!"
	msp, err := policy.BooleanToMSP("((清华 AND 计算机) OR (北大 AND 数学))", false)
	if err != nil {
		panic(err)
	}
	cipher, err := new_inst.Encrypt(msg, msp, &newPubkey)
	if err != nil {
		fmt.Println("Encrypt error:", err)
		return
	}
	cipherJson, err := json.Marshal(cipher)
	var newCipher ABECipher
	err = json.Unmarshal(cipherJson, &newCipher)

	//Decrypt
	decryptedMsg, err := new_inst.Decrypt(&newCipher, &newattribKeys, &newPubkey)
	if err != nil {
		fmt.Println("Decrypt error:", err)
		return
	}

	fmt.Println("Decrypted message:", decryptedMsg)
}
