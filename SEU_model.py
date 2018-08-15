#file to model the expectation of errors in LEO

def FaultInjection(AES_key, HMAC_key):
	#AES_key and HMAC_key are objects from KeyGen
	#returns flawed keys, depending on model

	#AES_key[0][1] = AES_key[0][1] * 2

	#HMAC_key[0][1] = HMAC_key[0][1] * 2

	return AES_key, HMAC_key