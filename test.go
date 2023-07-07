package main

import (
	"fmt"
	"example.com/playground/zsl"
)

func main() {
	api := zsl.NewPublicZSLAPI()

	init := false

	if (init) {
		zsl.CreateParamsUnshielding()
		zsl.CreateParamsUnshielding()
		zsl.CreateParamsTransfer()
	}


	keyPair, err := api.GenerateZKeypair()
	if err != nil {
		fmt.Println(err)
		return
	}
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