#keyring polynomial interpolation
#reference latex

import random
from pytictoc import TicToc

#solution 2a
#lam is the security parameter, which is 256 bits
def KeyGen(lam=32, num_chunks=4):

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
		ind = 2*i + 1
		chunk = random.getrandbits(chunk_size)
		PRF_chunks.append((ind, chunk))

	#bit strings of PRF chunks
	"""
	test_string = ""
	for i in range(0, len(PRF_chunks)):
		test_string += ChunkSize(str(bin(PRF_chunks[i][1]))[2:]) #demonstrates total PRF string
	"""
	
	#generate polynomials (lines) to interpolate and compute intermediate points
	GEN_chunks = []
	PRF_chunks.append(PRF_chunks[0]) # create ring
	for i in range(0, len(PRF_chunks)-1):
		X = PRF_chunks[i][0] + 1
		Y = (PRF_chunks[i+1][1] - PRF_chunks[i][1]) / (PRF_chunks[i+1][0] - PRF_chunks[i][0]) * (X - PRF_chunks[i][0]) + PRF_chunks[i][1]
		GEN_chunks.append((X,Y))
	#PRF_chunks.pop() #move from ring back to string

	return PRF_chunks, GEN_chunks


def Correctness(PRF_chunks, GEN_chunks):
	for i in range(0, len(PRF_chunks)-1):
		xval_forward = PRF_chunks[i+1][0]
		check_forward = (GEN_chunks[i][1] - PRF_chunks[i][1]) / (GEN_chunks[i][0] - PRF_chunks[i][0]) * (xval_forward - PRF_chunks[i][0]) + PRF_chunks[i][1]
		if check_forward != PRF_chunks[i+1][1]:
			return False
	#note GEN_chunks has one less index, is not a ring
	for i in range(len(PRF_chunks)-1, 0, -1):
		j = i - 1 #for GEN_chunks
		xval_backward = PRF_chunks[i][0]
		check_backward = (GEN_chunks[j][1] - PRF_chunks[i][1]) / (GEN_chunks[j][0] - PRF_chunks[i][0]) * (xval_backward - PRF_chunks[i][0]) + PRF_chunks[i][1]
		if check_backward != PRF_chunks[i-1][1]:
			return False
	return True

	Correctness(PRF_chunks, GEN_chunks)


def main():

	sets = KeyGen()

	valid_ring = Correctness(sets[0], sets[1])
	if valid_ring == False:
		while valid_ring == False:
			sets = KeyGen()
			valid_ring = Correctness(sets[0], sets[1])
		print "success"
	else:
		print "success"

	return

t = TicToc()
t.tic()
main()
t.toc()












