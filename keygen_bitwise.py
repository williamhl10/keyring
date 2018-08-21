#keygen_bitwise
#different generation algorithm for the ring

import random

class Parameters():

	def __init__(self):

		self.lam = 4
		self.num_chunks = 8 #if 256 then bits are generated, 8 for clock
		self.chunk_size = self.lam/(self.num_chunks/2) #divide by 2 since half are derived


#define parameters for KeyGen
P = Parameters()

lam = P.lam
num_chunks = P.num_chunks
chunk_size = P.chunk_size

class KeyGen():

	def __init__(self):

		#half = num_chunks/2

		self.ring = dict()

		for i in range(0, num_chunks, 2):

			self.ring.update({i : random.getrandbits(chunk_size)})

		for i in range(1, num_chunks, 2):

			val = self.ring[(i-1)%num_chunks] ^ self.ring[(i+1)%num_chunks]
			self.ring.update({i : val})

		#now form AES and HMAC keys
		self.AES = dict()
		self.HMAC = dict()

		self.xor_forward = []

		for loc in range(0, num_chunks/2):

			if loc % 2 == 0 and loc-2 not in self.AES: #ensure a PRF value and not in same joint

				self.AES.update({loc : self.ring[loc]})

				#print loc, loc-2

			#allow all generated values to pass
			elif loc % 2 == 1:

				self.AES.update({loc : self.ring[loc]})
				#print loc, loc-2

			#swapped values, keep track of values to XOR forward to spread entropy
			else:

				#print loc, (num_chunks/2+loc)

				#swap first
				self.AES.update({(num_chunks/2+loc) : self.ring[(num_chunks/2+loc)]})
				#now keep track of locations to xor forward
				#tuple of key locations: AES, HMAC
				self.xor_forward.append((num_chunks/2+loc, loc))

		print self.xor_forward

		for loc in self.ring:

			if loc not in self.AES:

				self.HMAC.update({loc : self.ring[loc]})

		#perform forward xor
		#print sorted(self.HMAC.keys())
		for aes_loc, hmac_loc in self.xor_forward:

			#print aes_loc, hmac_loc

			aes_change_val = hmac_loc+1
			hmac_change_val = aes_loc+1

			#print aes_change_val, hmac_change_val

			#print self.AES[aes_change_val]

			#print self.AES[aes_change_val] ^ self.ring[3] ^ self.ring[5]

			#print self.AES[7], self.ring[7]

			self.AES[aes_change_val] = self.AES[aes_change_val] ^ self.AES[aes_loc]

			#print self.AES[aes_change_val], self.ring[aes_change_val]

			self.HMAC[hmac_change_val] = self.HMAC[hmac_change_val] ^ self.HMAC[hmac_loc]


# key = KeyGen()

# # #print "ring", key.ring

# # #print "key AES", key.AES
# # #print "key HMAC", key.HMAC

# print key.AES[3] ^ key.ring[2] ^ key.ring[4] ^ key.ring[6]
# print key.HMAC[7] ^ key.ring[0] ^ key.ring[2] ^ key.ring[6]
# print key.AES[6] ^ key.HMAC[4] ^ key.HMAC[5]
# print key.HMAC[7] ^ key.ring[6] ^ key.ring[0] ^ key.ring[2]
#print key.ring[1] ^ key.ring[7]

def KeyReGen(AES_key, HMAC_key, xor_forward_tups):
	#function to regenerate keys in the event of radiation-induced error(s)

	bad_chunks = set()

	xor_forward_list = []
	changed_bits_xor_forward = []
	for i,j in xor_forward_tups:

		xor_forward_list.append(i)
		xor_forward_list.append(j)

		changed_bits_xor_forward.append((i+1)%num_chunks)
		changed_bits_xor_forward.append((j+1)%num_chunks)

	print changed_bits_xor_forward

	RING = dict()

	for i in AES_key:

		RING.update({i : AES_key[i]})

	for i in HMAC_key:

		RING.update({i : HMAC_key[i]})

	#print RING
	#print xor_forward_list

	#go through each chunk and check if its correct, based on clockwise neighbors
	for i in range(0, len(RING), 2):

		if i not in xor_forward_list:

			check_clockwise = RING[i] ^ RING[(i+2)%num_chunks]

			if check_clockwise != RING[i+1]:

				bad_chunks.add(i)
				bad_chunks.add((i+1)%num_chunks)
				bad_chunks.add((i+2)%num_chunks)
				print i, (i+1)%num_chunks, (i+2)%num_chunks

		#even points will be added to bad points as a result of the above
		#errors could be in i, i+1, or i+1

		else: #the point is in xor_forward_list

			check = RING[i] ^ RING[(i+2)%num_chunks] ^ RING[(i + num_chunks/2)%num_chunks]

			if check != RING[i+1]:

				print (i+1)%num_chunks
				bad_chunks.add((i+1)%num_chunks)

	bad_chunks = list(bad_chunks)

	print "bad bits", bad_chunks

	good_chunks = []

	for chunk in RING:

		if chunk not in bad_chunks:

			good_chunks.append(chunk)

	print "good bits", good_chunks

	#begin regen

	counter = 0
	regen = False

	while regen == False:

		counter += 1

		if counter > 10:

			break

		if len(bad_chunks) == 0:

			regen = True

		if len(bad_chunks) == 3:

			for ind in bad_chunks:

				if (ind-1)%num_chunks in bad_chunks and (ind+1)%num_chunks in bad_chunks:

					#check if the error is at the overlapping point

					#ind+2 can't be in the xor forward list, can only happen not neat the switched
					#points, otherwise there would be 4 bad points

					check_val = RING[(ind+1)%num_chunks]

					#compare across the ring to the xor forward point

					xor_back_check = RING[(ind-1)%num_chunks] ^ RING[(ind-2)%num_chunks]

					if check_val == xor_back_check:

						#the bordering bad points are correct, but throwing verification errors
						if ind in HMAC_key:

							HMAC_key[ind] = RING[(ind+1)%num_chunks] ^ RING[(ind+2)%num_chunks]
							bad_chunks.remove(ind)
							bad_chunks.remove((ind+1)%num_chunks)
							bad_chunks.remove((ind-1)%num_chunks)

						elif ind in AES_key:

							AES_key[ind] = RING[(ind+1)%num_chunks] ^ RING[(ind+2)%num_chunks]
							bad_chunks.remove(ind)
							bad_chunks.remove((ind+1)%num_chunks)
							bad_chunks.remove((ind-1)%num_chunks)

						regen = True


		else:

			for ind in bad_chunks:

				print ind

				if ind % 2 == 0: #PRF chunk, evens can't be in xor list

					if (ind+1)%num_chunks in changed_bits_xor_forward:

						print "layer"

						if (ind+1)%num_chunks in good_chunks and (ind+3)%num_chunks in good_chunks:

							if ind in HMAC_key:

								HMAC_key[ind] = RING[(ind+1)%num_chunks] ^ RING[(ind+3)%num_chunks]
								bad_chunks.remove(ind)

							elif ind in AES_key:

								AES_key[ind] = RING[(ind+1)%num_chunks] ^ RING[(ind+3)%num_chunks]
								bad_chunks.remove(ind)

					else: #next bit not in the xor forward list

						if (ind+1)%num_chunks in good_chunks and (ind+2)%num_chunks in good_chunks:

							if ind in HMAC_key:

								HMAC_key[ind] = RING[(ind+1)%num_chunks] ^ RING[(ind+2)%num_chunks]
								bad_chunks.remove(ind)

							elif ind in AES_key:

								AES_key[ind] = RING[(ind+1)%num_chunks] ^ RING[(ind+2)%num_chunks]
								bad_chunks.remove(ind)

				else: #GEN chunk, could itself be in the xor list

					if ind in xor_forward_list:

						if (ind+1)%num_chunks in good_chunks and (ind+3)%num_chunks in good_chunks:

							if ind in HMAC_key:

								HMAC_key[ind] = RING[(ind+1)%num_chunks] ^ RING[(ind+3)%num_chunks]
								bad_chunks.remove(ind)

							elif ind in AES_key:

								AES_key[ind] = RING[(ind+1)%num_chunks] ^ RING[(ind+3)%num_chunks]
								bad_chunks.remove(ind)

					else: #ind not in xor forwad list

						print "hi"

	print "counter", counter


	return AES_key, HMAC_key


key = KeyGen()

print "ring", key.ring

print "key no error", key.AES[0]
#print "key HMAC", key.HMAC

key.AES[0] = key.AES[0] ^ 1

print "key with error", key.AES[0]

key.AES, key.HMAC = KeyReGen(key.AES, key.HMAC, key.xor_forward)

print "key after", key.AES[0]

#print key.AES[4] ^ key.ring[3] ^ key.ring[5] ^ key.ring[7]
#print key.HMAC[8] ^ key.ring[1] ^ key.ring[3] ^ key.ring[7]
#print key.ring[1] ^ key.ring[7]

























