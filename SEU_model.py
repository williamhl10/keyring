#file to model the expectation of errors in LEO

import random
from keyring_gen import Parameters

#define security parameters for the scheme
P = Parameters()

lam = P.lam
num_chunks = P.num_chunks
chunk_size = P.chunk_size

def FaultInjection(AES_key, HMAC_key, AES_chunk=None, HMAC_chunk=None):
	#AES_key and HMAC_key are objects from KeyGen
	#returns flawed keys, depending on model

	#for targeted errors of entire chunk (not single bit)
	if AES_chunk != None:

		AES_key[AES_chunk][1] = AES_key[AES_chunk][1] ^ random.getrandbits(chunk_size)

	elif HMAC_chunk != None:

		HMAC_key[HMAC_chunk][1] = HMAC_key[HMAC_chunk][1] ^ random.getrandbits(chunk_size)

	else:

		AES_key[0][1] = AES_key[0][1] ^ random.getrandbits(chunk_size)

		#HMAC_key[2][1] = HMAC_key[2][1] ^ random.getrandbits(chunk_size)

	return AES_key, HMAC_key