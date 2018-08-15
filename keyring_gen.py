#keyring class for key generation

import random

class Parameters():

	def __init__(self):

		self.lam = 256
		self.num_chunks = 4
		self.chunk_size = self.lam/self.num_chunks


#define parameters for KeyGen
P = Parameters()

lam = P.lam
num_chunks = P.num_chunks
chunk_size = P.chunk_size


class KeyGen():
	#generated key by using PRF for a specified number of chunks
	#will xor to start

	#self.PRF is a list of the PFR variables as [ind, PRF at ind]
	#self.GEN is a list of the GEN variables as [ind, GEN at ind]

	def __init__(self):

			#create PRF list

			PRF_list = []
			PRF_inds = []

			for i in range(0, num_chunks):

				PRF_list.append([2*i+1, random.getrandbits(chunk_size)])
				PRF_inds.append(i)

			self.PRF = PRF_list

			#create GEN list

			GEN_list = []

			for i in range(0, len(PRF_list)):

				gen_val = PRF_list[i][1] ^ PRF_list[(i+1)%num_chunks][1]
				GEN_list.append([2*i+2, gen_val])

			self.GEN = GEN_list


			#create AES and HMAC keys
			AES_list = []
			HMAC_list = []

			half = len(self.PRF)/2
			count = 0

			for i in range(0, len(self.PRF)):

				if count < half:

					AES_list.append(self.PRF[i])
					AES_list.append(self.GEN[i])

				else:

					HMAC_list.append(self.PRF[i])
					HMAC_list.append(self.GEN[i])

				count += 1

			self.AES = AES_list
			self.HMAC = HMAC_list

			#perform swapping for maximum security

			for i in range(0, len(self.AES)):

				if self.AES[i][0] % 2 == 1 and self.AES[(i+2)%num_chunks][0] % 2 == 1: #make sure vals from PRF

					joint_member_test = self.AES[(i+2)%num_chunks][0] - 2 

					#assess if the PRF vals are on the same AES joint

					if self.AES[i][0] == joint_member_test:

						hold1 = self.AES[(i+2)%num_chunks]
						hold2 = self.HMAC[(i+2)%num_chunks]

						#think of peeling off half, note the symmetry of the ring

						self.AES[(i+2)%num_chunks] = hold2
						self.HMAC[(i+2)%num_chunks] = hold1
































