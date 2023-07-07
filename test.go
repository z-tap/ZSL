package main

import (
	"fmt"
	"example.com/playground/zsl"
)

func main() {
	api := zsl.NewPublicZSLAPI()
	// zsl.CreateParamsUnshielding()
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

}