#KeyRing main file

from keyring_gen import KeyGen, Parameters
from prettyprint import printKey
from ring_verification import InverseSwap, Verify
from SEU_model import FaultInjection
from keyring_regen import KeyReGen
from pytictoc import TicToc
from triple import TRbitComparison
from copy import deepcopy

#define security parameters for the scheme, from keyring_gen file
P = Parameters()

lam = P.lam
num_chunks = P.num_chunks
chunk_size = P.chunk_size

def main():

	"""initialize the key object, creates the key ring with security swapping"""

	key = KeyGen()

	if Verify(key.AES, key.HMAC) == True:

		print "Key Ring Created and Verified. Ready for Encryption."

	else:
		#attempt to regenerate the key

		print "Error in Key Ring Formation. Trying Again."
		return main()



	"""Simulate behavior in LEO by injecting faults into the system"""

	#print "before", key.AES
	#print "before", key.HMAC

	#simulate upsets to the system
	#for i in range(0, len(key.AES)): 

	#store copy for reference later (and use in triple redundancy)
	AES_copy = deepcopy(key.AES)
	HMAC_copy = deepcopy(key.HMAC)

	key.AES, key.HMAC = FaultInjection(key.AES, key.HMAC, None, None)

	AES_copy_error = deepcopy(key.AES)
	HMAC_copy_error = deepcopy(key.HMAC)


	#incorporates a timer, uses same error as in Key Ring
	TRbitComparison(AES_copy, HMAC_copy, AES_copy_error, HMAC_copy_error)

	#print "error", key.AES
	#print "error", key.HMAC


	"""Assess if the keys have incurred an SEU; if they have, attempt to regenerate the keys"""

	if Verify(key.AES, key.HMAC) == True:

		print "Key Ring Verified. Ready for Encryption."

	else:
		#attempt to regenerate the key

		print "Error in Key Ring... Locating..."

		#incorporates a timer
		key.AES, key.HMAC = KeyReGen(key.AES, key.HMAC)


		#print "fix", key.AES
		#print "fix", key.HMAC

		if Verify(key.AES, key.HMAC) == True:

			print "Key Ring Verified. Ready for Encryption."

		else:

			print "Error"





	"""Print the keys as strings"""
	#print printKey(key.AES, lam)
	#print printKey(key.HMAC, lam)

	return


main()

#print printKey(key.AES, lam)
