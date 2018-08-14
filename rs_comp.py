#Reed-Solomon comparison
import reedsolo
import random


rs = RSCodec(10)
message = random.getrandbits(256)
code = rs.encode(message, poly=False, k=None)

print code



