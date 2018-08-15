#file with functions to verify the key ring

from keyring_gen import Parameters

#define security parameters for the scheme
P = Parameters()

lam = P.lam
num_chunks = P.num_chunks
chunk_size = P.chunk_size


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

def ForwardSwap(PRF_set, GEN_set):
	#create AES and HMAC keys from PRF and GEN sets
	#sets are lists of lists such that [ind, val]

	AES_list = []
	HMAC_list = []

	half = len(PRF_set)/2
	count = 0

	for i in range(0, len(PRF_set)):

		if count < half:

			AES_list.append(PRF_set[i])
			AES_list.append(GEN_set[i])

		else:

			HMAC_list.append(PRF_set[i])
			HMAC_list.append(GEN_set[i])

		count += 1

	AES_key = AES_list
	HMAC_key = HMAC_list

	#perform chunk movement for maximum security

	for i in range(0, len(AES_key)):

		if AES_key[i][0] % 2 == 1 and AES_key[(i+2)%num_chunks][0] % 2 == 1: #make sure vals from PRF

			joint_member_test = AES_key[(i+2)%num_chunks][0] - 2 

			#assess if the PRF vals are on the same AES joint

			if AES_key[i][0] == joint_member_test:

				hold1 = AES_key[(i+2)%num_chunks]
				hold2 = HMAC_key[(i+2)%num_chunks]

				#think of peeling off half, note the symmetry of the ring

				AES_key[(i+2)%num_chunks] = hold2
				HMAC_key[(i+2)%num_chunks] = hold1

	return AES_key, HMAC_key


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



























