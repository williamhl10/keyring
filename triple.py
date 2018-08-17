#triple redundacy checker

import random
from pytictoc import TicToc
from SEU_model import FaultInjection
from copy import deepcopy
from keyring_gen import Parameters
from prettyprint import KeyOnly

#define security parameters for the scheme
P = Parameters()

lam = P.lam
num_chunks = P.num_chunks
chunk_size = P.chunk_size

class KeyObject():

	def __init__(self):

		self.AES = [[i, random.getrandbits(chunk_size)] for i in range(0, num_chunks)]
		self.HMAC = [[i, random.getrandbits(chunk_size)] for i in range(0, num_chunks)]



def Reset(chunk_copy_maj1, chunk_copy_maj2, chunk_copy_min):
	#function to reset keys in the event of dissent
	#resets copy3 to the majority with copy1 and copy2

	chunk_copy_min = deepcopy(chunk_copy_maj1)

	return chunk_copy_maj1, chunk_copy_maj2, chunk_copy_min


def TRbitComparisonTest():
	#function to compare strings bit by bit, searching for dissent
	key = KeyObject()

	#create three copies of each key for reundancy, in order to correct errors
	AEScopy1 = deepcopy(key.AES)
	AEScopy2 = deepcopy(key.AES)
	AEScopy3 = deepcopy(key.AES)

	HMACcopy1 = deepcopy(key.HMAC)
	HMACcopy2 = deepcopy(key.HMAC)
	HMACcopy3 = deepcopy(key.HMAC)

	#inject upset for testing
	AEScopy1, HMACcopy1 = FaultInjection(AEScopy1, HMACcopy1, None, None)
	#AEScopy2, HMACcopy2 = FaultInjection(AEScopy2, HMACcopy2, None, None)
	#AEScopy3, HMACcopy3 = FaultInjection(AEScopy3, HMACcopy3, None, None)

	#AEScopy1, HMACcopy1 = FaultInjection(AEScopy1, HMACcopy1, None, None)
	#AEScopy2, HMACcopy2 = FaultInjection(AEScopy2, HMACcopy2, None, None)
	#AEScopy3, HMACcopy3 = FaultInjection(AEScopy3, HMACcopy3, None, None)

	#make strings for comparisons
	#use list type for indexing and item assignment in the event of error
	AEScopy1_string = list(KeyOnly(AEScopy1))
	AEScopy2_string = list(KeyOnly(AEScopy2))
	AEScopy3_string = list(KeyOnly(AEScopy3))

	HMACcopy1_string = list(KeyOnly(HMACcopy1))
	HMACcopy2_string = list(KeyOnly(HMACcopy2))
	HMACcopy3_string = list(KeyOnly(HMACcopy3))

	t = TicToc()
	t.tic()

	#check for AES key
	for b in range(0, len(AEScopy1_string)):

		if AEScopy1_string[b] != AEScopy2_string[b]:

			if AEScopy1_string[b] == AEScopy3_string[b]:

				print "Reset AES 2"

				AEScopy2_string[b] = AEScopy1_string[b]

			else:
				#copy2 and copy3 must be the same
				print "Reset AES 1"
				AEScopy1_string[b] = AEScopy2_string[b]

		if AEScopy1_string[b] != AEScopy3_string[b]:
			print "Reset AES 3"
			#must be that copy1 and copy2 have majority
			AEScopy3_string[b] = AEScopy1_string[b]

	#check for HMAC key
	for b in range(0, len(HMACcopy1_string)):

		if HMACcopy1_string[b] != HMACcopy2_string[b]:

			if HMACcopy1_string[b] == HMACcopy3_string[b]:

				print "Reset HMAC 2"

				HMACcopy2_string[b] = HMACcopy1_string[b]

			else:
				#copy2 and copy3 must be the same
				print "Reset HMAC 1"
				HMACcopy1_string[b] = HMACcopy2_string[b]

		if HMACcopy1_string[b] != HMACcopy3_string[b]:
			print "Reset HMAC 3"
			#must be that copy1 and copy2 have majority
			HMACcopy3_string[b] = HMACcopy1_string[b]	


	t.toc("Triple Redundancy")

	return 

#TRbitComparisonTest()

def TRbitComparison(AES, HMAC, AES_error, HMAC_error):
	#create three copies of each key for reundancy, in order to correct errors
	AEScopy1 = deepcopy(AES)
	AEScopy2 = deepcopy(AES)
	AEScopy3 = deepcopy(AES)

	HMACcopy1 = deepcopy(HMAC)
	HMACcopy2 = deepcopy(HMAC)
	HMACcopy3 = deepcopy(HMAC)

	#inject upset (from Keyring) into the system at a random copy for AES
	error_copy_AES = random.randint(1,3)

	if error_copy_AES == 1:

		AEScopy1 = AES_error

	elif error_copy_AES == 2:

		AEScopy2 = AES_error

	else:

		AEScopy3 = AES_error

	#perform the above for the HMAC key
	error_copy_HMAC = random.randint(1,3)

	if error_copy_HMAC == 1:

		HMACcopy1 = HMAC_error

	elif error_copy_HMAC == 2:

		HMACcopy2 = HMAC_error

	else:

		HMACcopy3 = HMAC_error

	#make strings for comparisons
	#use list type for indexing and item assignment in the event of error
	AEScopy1_string = list(KeyOnly(AEScopy1))
	AEScopy2_string = list(KeyOnly(AEScopy2))
	AEScopy3_string = list(KeyOnly(AEScopy3))

	HMACcopy1_string = list(KeyOnly(HMACcopy1))
	HMACcopy2_string = list(KeyOnly(HMACcopy2))
	HMACcopy3_string = list(KeyOnly(HMACcopy3))

	t = TicToc()
	t.tic()

	#check for AES key
	for b in range(0, len(AEScopy1_string)):

		if AEScopy1_string[b] != AEScopy2_string[b]:

			if AEScopy1_string[b] == AEScopy3_string[b]:

				print "Reset AES 2"

				AEScopy2_string[b] = AEScopy1_string[b]

			else:
				#copy2 and copy3 must be the same
				print "Reset AES 1"
				AEScopy1_string[b] = AEScopy2_string[b]

		if AEScopy1_string[b] != AEScopy3_string[b]:
			print "Reset AES 3"
			#must be that copy1 and copy2 have majority
			AEScopy3_string[b] = AEScopy1_string[b]

	#check for HMAC key
	for b in range(0, len(HMACcopy1_string)):

		if HMACcopy1_string[b] != HMACcopy2_string[b]:

			if HMACcopy1_string[b] == HMACcopy3_string[b]:

				print "Reset HMAC 2"

				HMACcopy2_string[b] = HMACcopy1_string[b]

			else:
				#copy2 and copy3 must be the same
				print "Reset HMAC 1"
				HMACcopy1_string[b] = HMACcopy2_string[b]

		if HMACcopy1_string[b] != HMACcopy3_string[b]:
			print "Reset HMAC 3"
			#must be that copy1 and copy2 have majority
			HMACcopy3_string[b] = HMACcopy1_string[b]	


	t.toc("Triple Redundancy")

	return 



def TripleRedundancyTester():

	key = KeyObject()

	#create three copies of each key for reundancy, in order to correct errors
	AEScopy1 = deepcopy(key.AES)
	AEScopy2 = deepcopy(key.AES)
	AEScopy3 = deepcopy(key.AES)

	HMACcopy1 = deepcopy(key.HMAC)
	HMACcopy2 = deepcopy(key.HMAC)
	HMACcopy3 = deepcopy(key.HMAC)

	#print "initial", AEScopy1

	#inject upset to the system
	#for j in range(0, len(AEScopy1)):

	#print j

	AEScopy1, HMACcopy1 = FaultInjection(AEScopy1, HMACcopy1, None, None)
	#AEScopy2, HMACcopy2 = FaultInjection(AEScopy2, HMACcopy2, j, None)
	#AEScopy3, HMACcopy3 = FaultInjection(AEScopy3, HMACcopy3, j, None)

	#AEScopy1, HMACcopy1 = FaultInjection(AEScopy1, HMACcopy1, None, j)
	#AEScopy2, HMACcopy2 = FaultInjection(AEScopy2, HMACcopy2, None, j)
	#AEScopy3, HMACcopy3 = FaultInjection(AEScopy3, HMACcopy3, None, j)

	#print "Error", AEScopy1

	#measure complexity of correction based on chunk sizes
	#t = TicToc()
	#t.tic()

	#check for AES keys
	for i in range(0, len(AEScopy1)):

		#compare chunk by chunk
		if AEScopy1[i] != AEScopy2[i]:

			if AEScopy1[i] == AEScopy3[i]:
				#reset copy2
				print "Reset AES copy 2 at chunk", i
				AEScopy1[i], AEScopy3[i], AEScopy2[i] = Reset(AEScopy1[i], AEScopy3[i], AEScopy2[i])

			#if copy1 doesn't equal copy2, try comparing with copy3
			elif AEScopy1 != AEScopy3 and AEScopy2 == AEScopy3:
				#reset copy1
				print "Reset AES copy 1 at chunk", i
				AEScopy2[i], AEScopy3[i], AEScopy1[i] = Reset(AEScopy2[i], AEScopy3[i], AEScopy1[i])

			else:

				print "No chunks are equivalent"

		if AEScopy1[i] != AEScopy3[i]:
			#here we know copy1 and copy2 agree, need to make sure copy3 is the same
			#if not, reset copy3
			print "Reset AES copy 3 at chunk", i
			AEScopy1[i], AEScopy2[i], AEScopy3[i] = Reset(AEScopy1[i], AEScopy2[i], AEScopy3[i])

	#check for HMAC keys
	for i in range(0, len(HMACcopy1)):

		#compare chunk by chunk
		if HMACcopy1[i] != HMACcopy2[i]:

			if HMACcopy1[i] == HMACcopy3[i]:
				#reset copy2
				print "Reset HMAC copy 2 at chunk", i
				HMACcopy1[i], HMACcopy3[i], HMACcopy2[i] = Reset(HMACcopy1[i], HMACcopy3[i], HMACcopy2[i])

			#if copy1 doesn't equal copy2, try comparing with copy3
			elif HMACcopy1 != HMACcopy3 and HMACcopy2 == HMACcopy3:
				#reset copy1
				print "Reset HMAC copy 1 at chunk", i
				HMACcopy2[i], HMACcopy3[i], HMACcopy1[i] = Reset(HMACcopy2[i], HMACcopy3[i], HMACcopy1[i])

			else:

				print "No chunks are equivalent"

		if HMACcopy1[i] != HMACcopy3[i]:
			#here we know copy1 and copy2 agree, need to make sure copy3 is the same
			#if not, reset copy3
			print "Reset HMAC copy 3 at chunk", i
			HMACcopy1[i], HMACcopy2[i], HMACcopy3[i] = Reset(HMACcopy1[i], HMACcopy2[i], HMACcopy3[i])


	#print "Corrected", AEScopy1



	#t.toc("Triple Redundancy")

	return

#TripleRedundancyTester()

#for use to call for comparison in KeyRing
def TripleRedundancy(AES, HMAC, AES_error, HMAC_error):

	#create three copies of each key for reundancy, in order to correct errors
	AEScopy1 = deepcopy(AES)
	AEScopy2 = deepcopy(AES)
	AEScopy3 = deepcopy(AES)

	HMACcopy1 = deepcopy(HMAC)
	HMACcopy2 = deepcopy(HMAC)
	HMACcopy3 = deepcopy(HMAC)

	#inject upset (from Keyring) into the system at a random copy for AES
	error_copy_AES = random.randint(1,3)

	if error_copy_AES == 1:

		AEScopy1 = AES_error

	elif error_copy_AES == 2:

		AEScopy2 = AES_error

	else:

		AEScopy3 = AES_error

	#perform the above for the HMAC key
	error_copy_HMAC = random.randint(1,3)

	if error_copy_HMAC == 1:

		HMACcopy1 = HMAC_error

	elif error_copy_HMAC == 2:

		HMACcopy2 = HMAC_error

	else:

		HMACcopy3 = HMAC_error

	#measure complexity of correction based on chunk sizes
	t = TicToc()
	t.tic()

	#check for AES keys
	for i in range(0, len(AEScopy1)):

		#compare chunk by chunk
		if AEScopy1[i] != AEScopy2[i]:

			if AEScopy1[i] == AEScopy3[i]:
				#reset copy2
				print "Reset AES copy 2 at chunk", i
				AEScopy1[i], AEScopy3[i], AEScopy2[i] = Reset(AEScopy1[i], AEScopy3[i], AEScopy2[i])

			#if copy1 doesn't equal copy2, try comparing with copy3
			elif AEScopy1 != AEScopy3 and AEScopy2 == AEScopy3:
				#reset copy1
				print "Reset AES copy 1 at chunk", i
				AEScopy2[i], AEScopy3[i], AEScopy1[i] = Reset(AEScopy2[i], AEScopy3[i], AEScopy1[i])

			else:

				print "No chunks are equivalent"

		if AEScopy1[i] != AEScopy3[i]:
			#here we know copy1 and copy2 agree, need to make sure copy3 is the same
			#if not, reset copy3
			print "Reset AES copy 3 at chunk", i
			AEScopy1[i], AEScopy2[i], AEScopy3[i] = Reset(AEScopy1[i], AEScopy2[i], AEScopy3[i])

	#check for HMAC keys
	for i in range(0, len(HMACcopy1)):

		#compare chunk by chunk
		if HMACcopy1[i] != HMACcopy2[i]:

			if HMACcopy1[i] == HMACcopy3[i]:
				#reset copy2
				print "Reset HMAC copy 2 at chunk", i
				HMACcopy1[i], HMACcopy3[i], HMACcopy2[i] = Reset(HMACcopy1[i], HMACcopy3[i], HMACcopy2[i])

			#if copy1 doesn't equal copy2, try comparing with copy3
			elif HMACcopy1 != HMACcopy3 and HMACcopy2 == HMACcopy3:
				#reset copy1
				print "Reset HMAC copy 1 at chunk", i
				HMACcopy2[i], HMACcopy3[i], HMACcopy1[i] = Reset(HMACcopy2[i], HMACcopy3[i], HMACcopy1[i])

			else:

				print "No chunks are equivalent"

		if HMACcopy1[i] != HMACcopy3[i]:
			#here we know copy1 and copy2 agree, need to make sure copy3 is the same
			#if not, reset copy3
			print "Reset HMAC copy 3 at chunk", i
			HMACcopy1[i], HMACcopy2[i], HMACcopy3[i] = Reset(HMACcopy1[i], HMACcopy2[i], HMACcopy3[i])


	#print "Corrected", AEScopy1



	t.toc("Triple Redundancy")

	return
	




















