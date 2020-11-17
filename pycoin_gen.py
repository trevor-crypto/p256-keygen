from sys import stdin
from pycoin.ecdsa import secp256r1 as p256
from pycoin.encoding import sec, hexbytes
from pycoin.satoshi import der
from secrets import randbelow
from hashlib import sha256

generator = p256.secp256r1_generator
privKey = randbelow(generator.order())
pubKey = generator * privKey
sec_pub = sec.public_pair_to_sec(pubKey, compressed=False)
print("pub: ", hexbytes.b2h(sec_pub))
# message = stdin.read()
# message = "Hello, world!"
message = "{{\n  \"email\": \"test_user@crypto.com\",\n  \"pubkey\": \"{}\",\n  \"scheme\": \"secp256r1\",\n  \"nonce\": \"d425dadb98c32e0d23ee3664d4aad64b57debbc062653102b59bd74ce4f64ad7\"\n}}".format(
    hexbytes.b2h(sec_pub))
digest = sha256(message.encode("utf-8")).digest()
msg_hash = int.from_bytes(digest, byteorder="big")
signature = generator.sign(privKey, msg_hash)

print("message: ", message)
# print("priv: ", privKey)
der = der.sigencode_der(signature[0], signature[1])
# print("r:", signature[0])
# print("s:", signature[1])
print("sig: ", hexbytes.b2h(der))

valid = generator.verify(pubKey, msg_hash, signature)

print("valid: ", valid)
