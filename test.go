package main

import (
	"fmt"
	"example.com/playground/zsl"
	"example.com/playground/merkle"
)

func main() {

	init := false
	api := zsl.NewPublicZSLAPI()

	merkle_depth := uint(29)
	acc := merkle.InitMerkleApi()
	acc.Init(merkle_depth)

	if (init) {
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