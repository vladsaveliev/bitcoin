"""
Playing with curves, secret and public keys, and wallet address generation
"""

# secp256k1 uses a = 0, b = 7, so we're dealing with the curve y^2 = x^3 + 7 (mod p)
import random
from bitcoin.b58 import b58encode
from bitcoin.curve import Curve, Point, Generator
from bitcoin.identity import PublicKey


bitcoin_curve = Curve(
    p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    a=0x0000000000000000000000000000000000000000000000000000000000000000,  # a = 0
    b=0x0000000000000000000000000000000000000000000000000000000000000007,  # b = 7
)

G = Point(
    bitcoin_curve,
    x=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    y=0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8,
)

# we can verify that the generator point is indeed on the curve, i.e. y^2 = x^3 + 7 (mod p)
print("Generator is on the curve: ", G.is_on_curve())
print()

# some other totally random point will of course not be on the curve, _MOST_ likely
random.seed(1337)
x = random.randrange(0, bitcoin_curve.p)
y = random.randrange(0, bitcoin_curve.p)
print("Totally random point is not: ", bitcoin_curve.point_is_on_curve(x, y) == 0)

bitcoin_gen = Generator(
    G=G,
    # the order of G is known and can be mathematically derived
    n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
)

print(bitcoin_gen)

print(G)
print(G + G)

sk = 1
pk = G
print(f" secret key: {sk}\n public key: {(pk.x, pk.y)=}")
print(f"Verify the public key is on the curve: {pk.is_on_curve()=}")
# if it was 2, the public key is G + G:
sk = 2
pk = G + G
print(f" secret key: {sk}\n public key: {(pk.x, pk.y)=}")
print(f"Verify the public key is on the curve: {pk.is_on_curve()=}")
# etc.:
sk = 3
pk = G + G + G
print(f" secret key: {sk}\n public key: {(pk.x, pk.y)=}")
print(f"Verify the public key is on the curve: {pk.is_on_curve()=}")

# "verify" correctness
print(f'{G == 1*G=}')
print(f'{G + G == 2*G=}')
print(f'{G + G + G == 3*G=}')
print(f'{G + G + G + G == 4*G=}')

# efficiently calculate our actual public key!
secret_key = 1231
public_key = secret_key * G
print(f"{public_key.x=}\n{public_key.y=}")
print(f"Verify the public key is on the curve: {(public_key.y**2 - public_key.x**3 - 7) % bitcoin_curve.p == 0=}")

# we are going to use the develop's Bitcoin parallel universe "test net" for this demo, so net='test'
address = PublicKey.from_point(public_key).address(net='test', compressed=True)
print(address)
print()

# test b58encode
print('Encode:', b58encode(b'\x00\x0011322'))
print()

print("Our first Bitcoin identity:")
print("1. secret key: ", secret_key)
print("2. public key: ", (public_key.x, public_key.y))
print("3. Bitcoin address: ", address)
