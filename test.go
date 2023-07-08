package main

import (
	"fmt"
	// "log"
	"reflect"
	"encoding/hex"
    "github.com/glyff/glyff-node/common"
	"example.com/playground/zsl"
	"example.com/playground/merkle"
)

func main() {

	// genParam := false

	// From https://github.com/zcash/zcash/pull/994
	// depth 29 (over 268 million possible joinsplits)
	// merkle_depth := uint(29)

	// testZSL(genParam)
	// testMerkleTree(merkle_depth)
	testShieldOrd()
}


func testZSL(genParam bool) {
	api := zsl.NewPublicZSLAPI()

	if (genParam) {
		zsl.CreateParamsUnshielding()
		zsl.CreateParamsUnshielding()
		zsl.CreateParamsTransfer()
	}

	keyPair, err := api.GenerateZKeypair()
	fmt.Println(keyPair)

	result, err := api.DebugShielding()

	fmt.Println(result)
	fmt.Println(err)

	result_unshield, err_unshield := api.DebugUnshielding()

	fmt.Println(result_unshield)
	fmt.Println(err_unshield)

	result_shielded_tx, err_shielded_tx := api.DebugShieldedTransfer()

	fmt.Println(result_shielded_tx)
	fmt.Println(err_shielded_tx)	
}

func testMerkleTree(merkle_depth uint) {

	acc := merkle.InitMerkleApi()

	acc.Init(merkle_depth)
	acc.InsertCommitment("0x00")
	acc.GetWitness("0x00")

	exists := acc.CommitmentExists("0x00")

	// fmt.Println(index)
	// fmt.Println(uncles)
	fmt.Println(exists)
}


func testShieldOrd() {
	api := zsl.NewPublicZSLAPI()

	keyPair, _ := api.GenerateZKeypair()
	fmt.Printf("Type of keyPair[\"a_pk\"]: %v\n", reflect.TypeOf(keyPair["a_pk"]))

	a_pk, _ := keyPair["a_pk"].(common.Hash)
	a_sk, _ := keyPair["a_sk"].(common.Hash)

	fmt.Println(a_pk)

	rho, _ := api.GetRandomness()
	fmt.Println(rho)

	value := float64(1000)

	result, _ := api.CreateShielding(rho, a_pk, value)
	fmt.Println(result)

	cm := result["cm"].(common.Hash)
	fmt.Println(cm)

	cmString := hex.EncodeToString(cm[:])
	fmt.Println(cmString)

	acc := merkle.InitMerkleApi()
	fmt.Printf("Type of acc: %v\n", reflect.TypeOf(acc))

	acc.Init(29)

	exists := acc.CommitmentExists(cmString)

	if (exists) {
		fmt.Println("Commitment already exists")
		return
	}

	result_shielding, _ := api.VerifyShielding(
		result["proof"].(string), 
		result["send_nf"].(common.Hash), 
		cm, 
		value,
	)

	fmt.Println(result_shielding)

	if (result_shielding) {
		acc.InsertCommitment(cmString)
		acc.GetWitness(cmString)
	}

	//TODO: Remove value from circulation with a BRC-20 transfer
	//TODO: Transmit an hash of the commitment on chain

	unshieldOrd(acc, rho, a_pk, a_sk, value)

}

func unshieldOrd(
	acc *merkle.PublicMarkleTreeAPI, 
	rho common.Hash, 
	a_pk common.Hash,
	a_sk common.Hash,
	value float64,
) {
	api := zsl.NewPublicZSLAPI()

	cm := api.GetCommitment(rho, a_pk, value)

	cmString := hex.EncodeToString(cm[:])
	fmt.Println(cmString)

	treeIndex, merklePath := acc.GetWitness(cmString)

	fmt.Println(treeIndex)
	fmt.Println(merklePath)

	root := acc.GetRoot()

	fmt.Println(root)

	addr := common.HexToAddress("0x00")

	result_unshielding, _ := api.CreateUnshielding(rho, a_sk, addr, value, float64(treeIndex), merklePath)

	fmt.Println(result_unshielding)

}