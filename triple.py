#triple redundacy check

import random
from pytictoc import TicToc

chunk_key = random.getrandbits(256)

print "first key", chunk_key

chunkCopy1 = chunk_key
chunkCopy2 = chunk_key

chunkslist = [chunk_key, chunkCopy1, chunkCopy2]

chunkslist[0] = chunkslist[0]*2
print "error injected"
print "erroneous key", chunkslist[0]

t = TicToc()

t.tic()
count = 0
for chunk in chunkslist[1:]:

	if chunk != chunk_key and count < 1:
		count += 1
	elif chunk != chunk_key and count == 1:
		chunk_key = chunk

print "new majority key"
print chunk_key
t.toc()
	



