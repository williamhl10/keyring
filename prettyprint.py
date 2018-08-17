#file to print the keys

from keyring_gen import Parameters

#define security parameters for the scheme
P = Parameters()

lam = P.lam
num_chunks = P.num_chunks
chunk_size = P.chunk_size

#key is either AES list or HMAC list

def printKey(key):

	key_as_string = ""

	for i in range(0, len(key)):
		key_as_string += str(bin(key[i][1]))[2:] #demonstrates total key string

	#in case length isn't the security parameter
	dif = lam - len(key_as_string)
	if dif != 0:

		for i in range(0, dif):
			
			key_as_string = "0" + key_as_string


	return "%d bit AES key: %s" % (len(key_as_string), key_as_string)

def KeyOnly(key):

	key_as_string = ""

	for i in range(0, len(key)):
		key_as_string += str(bin(key[i][1]))[2:] #demonstrates total key string

	#in case length isn't the security parameter
	dif = lam - len(key_as_string)
	if dif != 0:

		for i in range(0, dif):
			
			key_as_string = "0" + key_as_string


	return key_as_string
