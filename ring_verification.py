#file with functions to verify the key ring

global lam, num_chunks, chunk_size

#define security parameters for the scheme
lam = 256
num_chunks = 4
chunk_size = lam/num_chunks

def InverseSwap(AES_key, HMAC_key):
	#function to move back to PRF and GEN sets from AES and HMAC sets
	#AES_key and HMAC_key are objects from KeyGen

	PRF_set = []
	GEN_set = []

	for i in range(0 , len(AES_key)):

		#unpacking AES key
		if AES_key[i][0] % 2 == 1:

			PRF_set.append(AES_key[i])

		else:

			GEN_set.append(AES_key[i])

		#unpacking HMAC key
		if HMAC_key[i][0] % 2 == 1:

			PRF_set.append(HMAC_key[i])

		else:

			GEN_set.append(HMAC_key[i])

		#sort to get order back

		PRF_set.sort(key=lambda ind: ind[0])
		GEN_set.sort(key=lambda ind: ind[0])

	return PRF_set, GEN_set


def Verify(AES_key, HMAC_key):
	#function to verify the correctness of the key ring
	#AES_key and HMAC_key are objects from KeyGen

	PRF, GEN = InverseSwap(AES_key, HMAC_key)

	for i in range(0, len(PRF)):

		check_forward = PRF[i][1] ^ GEN[i][1]

		if check_forward != PRF[(i+1)%num_chunks][1]:

			return False

	for i in range(len(PRF)-1, 0, -1):

		j = (i - 1) % num_chunks #for GEN_chunks
		check_backward = PRF[i][1] ^ GEN[j][1]

		if check_backward != PRF[(i-1)%num_chunks][1]:

			return False

	return True



























