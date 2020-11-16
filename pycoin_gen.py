
from pycoin.ecdsa import secp256r1 as p256
from pycoin.encoding import sec, hexbytes
from pycoin.satoshi import der
from secrets import randbelow
from hashlib import sha256

generator = p256.secp256r1_generator
privKey = randbelow(generator.order())
pubKey = generator * privKey

message = "Hello, world!"
digest = sha256(message.encode("utf-8")).digest()
msg_hash = int.from_bytes(digest, byteorder="big")
signature = generator.sign(privKey, msg_hash)

print("message: ", message)
# print("priv: ", privKey)
der = der.sigencode_der(signature[0], signature[1])
print("r:", signature[0])
print("s:", signature[1])
print("sig: ", hexbytes.b2h(der))

valid = generator.verify(pubKey, msg_hash, signature)

print("valid: ", valid)

sec_pub = sec.public_pair_to_sec(pubKey, compressed=False)
print("pub: ", hexbytes.b2h(sec_pub))
