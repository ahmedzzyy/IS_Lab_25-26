from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util import number


class Subsystem:
    def __init__(self, name, p, g, rsa_bits=2048, dh_bits=512):
        self.name = name

        self.rsa = RSA.generate(rsa_bits)
        self.pub_rsa = self.rsa.publickey()

        self.p = p
        self.g = g

    def sign(self, msg: bytes):
        return pkcs1_15.new(self.rsa).sign(SHA256.new(msg))

    def verify(self, pub, msg: bytes, sig: bytes):
        try:
            pkcs1_15.new(pub).verify(SHA256.new(msg), sig)
            return True
        except Exception:
            return False

    def dh_offer(self):
        self.priv = number.getRandomRange(2, self.p - 2)
        self.pub = pow(self.g, self.priv, self.p)

        return self.pub, self.sign(str(self.pub).encode())

    def dh_accept(self, peer_pub, peer_sig, peer_rsa):
        if not self.verify(peer_rsa, str(peer_pub).encode(), peer_sig):
            raise Exception("Signature check failed!")

        self.priv = number.getRandomRange(2, self.p - 2)
        self.pub = pow(self.g, self.priv, self.p)

        shared = pow(peer_pub, self.priv, self.p)
        self.session_key = SHA256.new(str(shared).encode()).digest()

        return self.pub, self.sign(str(self.pub).encode())

    def dh_finish(self, peer_pub, peer_sig, peer_rsa):
        if not self.verify(peer_rsa, str(peer_pub).encode(), peer_sig):
            raise Exception("Signature check failed in finish!")

        shared = pow(peer_pub, self.priv, self.p)
        self.session_key = SHA256.new(str(shared).encode()).digest()


# -------- Demo: A <-> B handshake --------
P = number.getPrime(512)
G = 2

A = Subsystem("Finance", P, G)
B = Subsystem("HR", P, G)

# A sends DH offer (signed with RSA)
a_pub, a_sig = A.dh_offer()
# B verifies and responds
b_pub, b_sig = B.dh_accept(a_pub, a_sig, A.pub_rsa)
# A finishes and derives the same key
A.dh_finish(b_pub, b_sig, B.pub_rsa)

print("Finance session key : ", A.session_key.hex()[:32], "...")
print("HR session key      : ", B.session_key.hex()[:32], "...")
print("Keys match?           ", A.session_key == B.session_key)
