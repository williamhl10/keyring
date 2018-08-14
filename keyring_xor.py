#keyring xor

import random
from pytictoc import TicToc

global num_chunks
num_chunks = 4

#solution 2a
#lam is the security parameter, which is 256 bits
def KeyGen(lam=256):

	chunk_size = lam/num_chunks

	#function to correct bit length of PRF strings
	def ChunkSize(chunk, size=chunk_size):
		if len(chunk) != size:
			dif = size - len(chunk)
			for i in range(0,dif):
				chunk = "0" + chunk
		return chunk

	#PRF generated chunks
	PRF_chunks = []
	for i in range(0, num_chunks):
		chunk = random.getrandbits(chunk_size)
		PRF_chunks.append(chunk)

	#bit strings of PRF chunks
	"""
	test_string = ""
	for i in range(0, len(PRF_chunks)):
		test_string += ChunkSize(str(bin(PRF_chunks[i][1]))[2:]) #demonstrates total PRF string
	"""
	
	#generate new strings by XOR operation
	GEN_chunks = []
	PRF_chunks.append(PRF_chunks[0]) # create ring
	for i in range(0, len(PRF_chunks)-1):
		middle = PRF_chunks[i] ^ PRF_chunks[i+1]
		GEN_chunks.append(middle)
	PRF_chunks.pop()
	#PRF_chunks.pop() #move from ring back to string

	return PRF_chunks, GEN_chunks

def Correctness(PRF_chunks, GEN_chunks):

	for i in range(0, len(PRF_chunks)):
		check_forward = PRF_chunks[i] ^ GEN_chunks[i]
		if check_forward != PRF_chunks[(i+1)%num_chunks]:
			return False
	#note GEN_chunks has one less index, is not a ring
	for i in range(len(PRF_chunks)-1, 0, -1):
		j = (i - 1) % num_chunks #for GEN_chunks
		check_backward = PRF_chunks[i] ^ GEN_chunks[j]
		if check_backward != PRF_chunks[(i-1)%num_chunks]:
			return False

	return True

#set1 is the PRF set and set2 is the generated set of strings
def SecuritySwap(set1, set2):

	key_set1 = []
	key_set1_inds = []
	key_set2 = []
	key_set2_inds = []

	swapped_inds = [] #list of indices where values in PRF and GEN were swapped, help for InverseSwap

	#form key sets
	for i in range(0, len(set1)):
		if len(key_set1) <= len(set1)/2:
			key_set1.append(set1[i])
			key_set1_inds.append(2*i+1)
			key_set1.append(set2[i])
			key_set1_inds.append(2*i+2)
		else:
			key_set2.append(set1[i])
			key_set2_inds.append(2*i+1)
			key_set2.append(set2[i])
			key_set2_inds.append(2*i+2)

	#perform swap for maximum security
	for elt in key_set1_inds:
		joint_member = elt - 2
		#check if more than 2 PRF values are in the same joint, must be odd since they're random
		if (joint_member in key_set1_inds) and (elt % 2 == 1 and joint_member % 2 == 1):
			swap1_inds = elt
			swap1 = key_set1[elt-1]
			swap2_inds = key_set2_inds[elt-1]
			swap2 = key_set2[elt-1]
			key_set1_inds[elt-1] = swap2_inds
			key_set1[elt-1] = swap2
			key_set2_inds[elt-1] = swap1_inds
			key_set2[elt-1] = swap1
			swapped_inds.append(elt-1)

	#print swapped_inds, key_set1_inds, key_set2_inds

	return key_set1, key_set1_inds, key_set2, key_set2_inds, swapped_inds

def InverseSwap(AES, HMAC, AES_inds, HMAC_inds, swapped_inds):
	#perform inverse swap for the KeyReGen function
	#swapped_inds contains the indices of elements to be swapped back
	#essentially moving from AES and HMAC form back to PRF and GEN form

	#first swap back the swapped index, which was done for security
	for i in swapped_inds:

		swap1 = AES[i]
		swap2 = HMAC[i]
		AES[i] = swap2
		HMAC[i] = swap1
		hold1 = AES_inds[i]
		hold2 = HMAC_inds[i]
		AES_inds[i] = hold2
		HMAC_inds[i] = hold1


	iswapPRF = []
	iswapGEN = []

	#need to iterate over AES key first to maintain ordering
	for i in range(0, len(AES)):

		if AES_inds[i] % 2 == 1:
			iswapPRF.append(AES[i])
		else:
			iswapGEN.append(AES[i])

	#now iterate over HMAC key
	for i in range(0, len(HMAC)):

		if HMAC_inds[i] % 2 == 1:
			iswapPRF.append(HMAC[i])
		else:
			iswapGEN.append(HMAC[i])

	return iswapPRF, iswapGEN


def KeyReGen(PRF, GEN, swapped_inds):
	#check if key has been damamged and then correct it

	#function to locate the location of AES and HMAC errors from PRF and GEN locations
	def LocateError(ind_PRF, ind_GEN):

		if ind_PRF == None:
			print ind_GEN
			#GEN ind is the one to explore
			if ind_GEN not in swapped_inds:
				if ind_GEN < len(GEN)/2:
					#in AES key
					location = (2*ind_GEN + 1) % num_chunks
					print "hey"
					note = "AES"
				else:
					#in HMAC key
					location = (2*ind_GEN + 1) % num_chunks
					note = "HMAC"

		else:
			print ind_PRF
			#PRF is the ind to explore
			if ind_PRF not in swapped_inds:
				if ind_PRF < len(PRF)/2:
					#in AES key
					location = (2*ind_PRF) % num_chunks
					print "hi"
					note = "AES"
				else:
					#in HMAC key
					location = (2*ind_PRF) % num_chunks
					note = "HMAC"

		return location, note

	#create ring
	#PRF.append(PRF[0])
	#create list of points involved in an error
	PRF_errors = set()
	GEN_errors = set()

	#check if any errors occured
	# xor_all = 0
	# comp = 0
	# for i in range(0, len(PRF)-1):

	# 	xor_all = xor_all ^ PRF[i] ^ GEN[i]
	# 	comp = comp ^ PRF[i]
	
	# if xor_all == comp:
	# 	return "Ready for Encryption"


	#error detection
	for i in range(0, len(PRF)):

		check = PRF[i] ^ PRF[(i+1)%num_chunks]
		if GEN[i] != check:
			PRF_errors.add(i)
			PRF_errors.add((i+1)%num_chunks)
			GEN_errors.add(i)

		# check = PRF[i] ^ GEN[i]
		# if PRF[i+1] != check:
		# 	PRF_errors.add(i)
		# 	PRF_errors.add(i+1)
		# 	GEN_errors.add(i)

	# for i in range(0, len(GEN)):
	# 	check = GEN[i] ^ PRF[i+1]
	# 	if PRF[i] != check:
	# 		PRF_errors.add(i)
	# 		PRF_errors.add(i+1)
	# 		GEN_errors.add(i)

	if len(PRF_errors) == 0 and len(GEN_errors) == 0:
		print "No errors found"
		return PRF, GEN
	else:
		print "Error in Cryptographic Key... Locating..."


	#error correction
	#print PRF_errors, GEN_errors

	for i in range(0, len(PRF)):

		#print "on", i
		if i in PRF_errors and (i-1)%num_chunks not in PRF_errors:

			check1 = PRF[i] ^ PRF[(i-1)%num_chunks]
			if check1 == GEN[(i-1)%num_chunks]:

				#print "PRF removed", i
				PRF_errors.remove(i)
				if (i-1)%num_chunks in GEN_errors:
					#print "GEN removed", (i-1)%num_chunks
					GEN_errors.remove((i-1)%num_chunks)

			check2 = PRF[i] ^ PRF[(i+1)%num_chunks]
			if check2 == GEN[i]:

				#print "PRF removed", i
				if i in PRF_errors:
					PRF_errors.remove(i)
				if i in GEN_errors:
					#print "GEN removed", i
					GEN_errors.remove(i)

		elif i in PRF_errors and (i+1)%num_chunks not in PRF_errors:

			#print "hey"

			check = PRF[i] ^ PRF[(i+1)%num_chunks]
			if check == GEN[i]:

				#print "PRF removed", i
				PRF_errors.remove(i)
				if i in GEN_errors:
					#print "GEN removed", i
					GEN_errors.remove(i)

		if len(PRF_errors) == 1 and len(GEN_errors) == 2:
			#PRF damaged and neighboring GEN strings also throwing errors
			#print "hi" 

			ind = list(GEN_errors)[0]
			if ind not in PRF_errors:

				test = PRF[ind] ^ GEN[ind]

				if test ^ GEN[(ind+1)%num_chunks] == PRF[(ind+2)%num_chunks]:

					PRF[(ind+1)%num_chunks] = test
					print "Error found in location %d of %s key. Corrected." % (LocateError(ind, None))
					break

			else:

				test = PRF[(ind+1)%num_chunks] ^ GEN[ind]

				if test ^ GEN[(ind-1)%num_chunks] == PRF[(ind-1)%num_chunks]:

					PRF[ind] = test
					print "Error found in location %d of %s key. Corrected." % (LocateError(ind, None))
					break

		elif len(PRF_errors) == 0 and len(GEN_errors) == 1:
			#error in one GEN

			ind = list(GEN_errors)[0]

			GEN[ind] = PRF[ind] ^ PRF[(ind+1)%num_chunks]
			print "Error found in location %d of %s key. Corrected." % (LocateError(None, ind))
			break


	#print PRF_errors, GEN_errors

	return PRF, GEN

def FaultInjection(AES, HMAC):
	#AES[1] = AES[1] * 2
	#HMAC[0] = HMAC[0] * 2
	return AES, HMAC


def main():

	"""generate key ring
	"""

	print("----------")
	t = TicToc()
	t.tic()
	PRF, GEN = KeyGen()
	t.toc("Key Generation:")
	print("----------")

	#print "to begin", PRF, GEN



	"""smooth ring just in case
	"""

	valid_ring = Correctness(PRF, GEN)
	if valid_ring == False:
		while valid_ring == False:
			sets = KeyGen()
			valid_ring = Correctness(PRF, GEN)
		print "Key Ring Verified"
	else:
		print "Key Ring Verified"

	print("----------")



	"""perform swapping to achieve security
	"""
	#not only performs center swap for added security, but also shuffles
	#the PRF and GEN values to achieve the desired level of security

	AES_key_set, AES_inds, HMAC_key_set, HMAC_inds, swapped_inds = SecuritySwap(PRF, GEN)
	#concatenate elts in sets to form keys, we refrain for testing
	#swapped inds constains the inds of swapped elts for security
	#AES has [1,2,7,4]
	#HMAC has [5,6,3,8]


	"""inject faults to test KeyReGen, which looks for and corrects errors
	"""
	#note that the inputs are not the swapped inputs, swapped inputs are
	#the keys, for AES and HMAC, includes security swapping
	AES_fault, HMAC_fault = FaultInjection(AES_key_set, HMAC_key_set)


	#print PRF
	"""inverse swap so that key can be regenerated
	"""
	#swap back key sets to PRF and GEN form for regen
	PRF_iswap_fault, GEN_iswap_fault = InverseSwap(AES_fault, HMAC_fault, AES_inds, HMAC_inds, swapped_inds)

	#print "swapped back", PRF_iswap_fault, GEN_iswap_fault


	"""Perform KeyReGen and measure complexity of regeneration
	"""
	#takes input in original PRF, GEN form, not the keyset form
	t = TicToc()
	t.tic()
	regen_PRF, regen_GEN = KeyReGen(PRF_iswap_fault, GEN_iswap_fault, swapped_inds)
	t.toc("Key Regeneration:")
	print "----------"

	#print "regen", regen_PRF, regen_GEN

	"""Test final correctness
	"""

	if Correctness(regen_PRF, regen_GEN) == True:
		print "Verified. Ready for Encryption."
	else:
		print "Error"

	return



main()



























