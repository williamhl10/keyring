#file to model the expectation of errors in LEO

def FaultInjection(AES_key, HMAC_key, AES_ind=None, HMAC_ind=None):
	#AES_key and HMAC_key are objects from KeyGen
	#returns flawed keys, depending on model

	#for targeted errors
	if AES_ind != None:

		AES_key[AES_ind][1] = AES_key[AES_ind][1] * 2

	elif HMAC_ind != None:

		HMAC_key[HMAC_ind][1] = HMAC_key[HMAC_ind][1] * 2

	else:

		AES_key[0][1] = AES_key[0][1] * 2

		HMAC_key[0][1] = HMAC_key[0][1] * 2

	return AES_key, HMAC_key