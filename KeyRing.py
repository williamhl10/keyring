#KeyRing main file

from keyring_gen import KeyGen
from prettyprint import printKey
from ring_verification import InverseSwap
from ring_verification import Verify
from SEU_model import FaultInjection

global lam, num_chunks, chunk_size

#define security parameters for the scheme
lam = 256
num_chunks = 4
chunk_size = lam/num_chunks

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

	key.AES, key.HMAC = FaultInjection(key.AES, key.HMAC)



	"""Assess if the keys have incurred an SEU; if they have, attempt to regenerate the keys"""

	if Verify(key.AES, key.HMAC) == True:

		print "Key Ring Verified. Ready for Encryption"

	else:
		#attempt to regenerate the key

		print "Error in Key Ring... Locating... "



	"""Print the keys as strings"""
	#print printKey(key.AES, lam)
	#print printKey(key.HMAC, lam)

	return


main()

#print printKey(key.AES, lam)
