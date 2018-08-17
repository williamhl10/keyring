#file for key regeneration in the event of an SEU

from ring_verification import InverseSwap, ForwardSwap
from keyring_gen import Parameters
from pytictoc import TicToc

#define security parameters for the scheme
P = Parameters()

lam = P.lam
num_chunks = P.num_chunks
chunk_size = P.chunk_size

def KeyReGen(AES_error, HMAC_error):
	#AES_error and HMAC_error are objects from KeyGen that have
	#been damaged by FaultInjection to simulate behavior in LEO

	t = TicToc()
	t.tic()

	PRF_error, GEN_error = InverseSwap(AES_error, HMAC_error)

	PRF_error_locations = set()
	GEN_error_locations = set()

	#define list of tuples which represent undamaged joints in the ring
	clean_joints = []

	"""pin the locations of the errors"""

	for i in range(0, len(PRF_error)):

		check_clockwise = PRF_error[i][1] ^ GEN_error[i][1]

		if check_clockwise != PRF_error[(i+1)%num_chunks][1]:

			check_counter_clockwise = PRF_error[i][1] ^ GEN_error[(i-1)%num_chunks][1]

			if check_counter_clockwise != PRF_error[(i-1)%num_chunks][1]:

				PRF_error_locations.add(i)

		else:
			#try to find all correct joints
				
			clean_joints.append((i,(i+1)%num_chunks))


	for i in range(0, len(GEN_error)):

		check = GEN_error[i][1] ^ PRF_error[i][1]

		if check != PRF_error[(i+1)%num_chunks][1]:

			GEN_error_locations.add(i)

	print PRF_error_locations, GEN_error_locations, clean_joints

	"""Statements about error locations for single error events"""

	if len(PRF_error_locations) == 1 and len(GEN_error_locations) == 0:
		#PRF error location only inside set because there is an error in a neighboring GEN

		loc = list(PRF_error_locations)[0]
		#print "Error found in AES key"
		correct_val = PRF_error[loc+1][1] ^ GEN_error[loc][1]

		#correct the value
		#print loc, PRF_error[loc]
		#correct location for AES key
		PRF_error[loc] = [(2*loc+1), correct_val]

	elif len(PRF_error_locations) == 1 and len(GEN_error_locations) == 2:
		#PRF error location inside set because there is an error in a neighboring two GENs

		loc = list(PRF_error_locations)[0]
		# print "Error found in  key"
		correct_val = PRF_error[(loc+1)%num_chunks][1] ^ GEN_error[loc][1]

		#correct the value
		#print loc, PRF_error[loc]
		#correct location for AES key
		PRF_error[loc] = [(2*loc+1), correct_val]

	elif len(PRF_error_locations) == 0 and len(GEN_error_locations) == 1:
		#GEN error location

		loc = list(GEN_error_locations)[0]
		#print "Error found in AES key"
		correct_val = PRF_error[loc][1] ^ PRF_error[(loc+1)%num_chunks][1]

		#correct location for AES key
		GEN_error[loc] = [2*loc+2, correct_val]

	"""Perform for multi-bit upsets"""




	#print PRF_error_locations, GEN_error_locations

	#print "hi", PRF_error, GEN_error

	#once the errors have been corrected, move to reform the key from the PRF and GEN sets
	AES_fix, HMAC_fix = ForwardSwap(PRF_error, GEN_error)

	t.toc("Key Ring")

	return AES_fix, HMAC_fix















