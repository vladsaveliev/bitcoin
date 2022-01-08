"""
Utilities to generate secret/public key pairs and Bitcoin address
(note: using "secret" instead of "private" so that sk and pk are
easy consistent shortcuts of the two without collision)
"""
import os
from dataclasses import dataclass, field
from typing import Union, Tuple, Optional

from .b58 import b58encode
from .bitcoin import BITCOIN
from .curve import Point
from .sha256 import sha256
from .ripemd160 import ripemd160


# -----------------------------------------------------------------------------
# Secret key generation. We're going to leave secret key as just a super plain int
from .transaction import Net


def gen_random_secret_key(n: int) -> int:
    """
    n is the upper bound on the key, typically the order of the elliptic curve
    we are using. The function will return a valid key, i.e. 1 <= key < n.
    """
    while True:
        key = int.from_bytes(os.urandom(32), 'big')
        if 1 <= key < n:
            break  # the key is valid, break out
    return key


# -----------------------------------------------------------------------------
# Public key - specific functions, esp encoding / decoding

class PublicKey(Point):
    """
    The public key is just a Point on a Curve, but has some additional specific
    encoding / decoding functionality that this class implements.
    """

    @classmethod
    def from_point(cls, pt: Point) -> 'PublicKey':
        """ 
        Promote a Point to be a PublicKey 
        """
        return cls(pt.curve, pt.x, pt.y)
    
    @classmethod
    def from_sk(cls, sk: Union[int, str]):
        """
        sk can be an int or a hex string 
        """
        assert isinstance(sk, (int, str))
        sk = int(sk, 16) if isinstance(sk, str) else sk
        pk = sk * BITCOIN.gen.G
        return cls.from_point(pk)

    def encode(self, compressed, hash160=False) -> bytes:
        """
        Return the SEC bytes encoding of the public key Point
        """
        # calculate the bytes
        if compressed:
            # (x,y) is very redundant. Because y^2 = x^3 + 7,
            # we can just encode x, and then y = +/- sqrt(x^3 + 7),
            # so we need one more bit to encode whether it was the + or the -
            # but because this is modular arithmetic there is no +/-, instead
            # it can be shown that one y will always be even and the other odd.
            prefix = b'\x02' if self.y % 2 == 0 else b'\x03'
            pkb = prefix + self.x.to_bytes(32, 'big')
        else:
            pkb = b'\x04' + self.x.to_bytes(32, 'big') + self.y.to_bytes(32, 'big')
        # hash if desired
        return ripemd160(sha256(pkb)) if hash160 else pkb

    def address(self, net: Net, compressed: bool) -> str:
        """ return the associated bitcoin address for this public key as string """
        # encode the public key into bytes and hash to get the payload
        pkb_hash = self.encode(compressed=compressed, hash160=True)
        # add version byte
        ver_pkb_hash = net.value + pkb_hash
        # calculate the checksum
        checksum = sha256(sha256(ver_pkb_hash))[:4]
        # append to form the full 25-byte binary Bitcoin Address
        byte_address = ver_pkb_hash + checksum
        # finally b58 encode the result
        b58check_address = b58encode(byte_address)
        return b58check_address
    

def gen_key_pair(passphrase: Optional[bytes] = None) -> Tuple[int, PublicKey]:
    """
    Generate a (secret, public) key pair in one shot.

    If passphrase is not provided, will generate a random secret key.
    """
    if passphrase is None:
        sk = gen_random_secret_key(BITCOIN.gen.n)
    else:
        sk = int.from_bytes(passphrase, 'big')
    assert 1 <= sk < BITCOIN.gen.n  # check it's valid
    return sk, PublicKey.from_sk(sk)


@dataclass
class Identity:
    secrey_key: int
    public_key: PublicKey
    address: str
    pkb_hash: bytes

    def __repr__(self):
        return (
            f'{self.__class__.__name__}('
            f'pkb_hash={self.pkb_hash.hex()}, '
            f'address={self.address}, '
            f'sk={self.secrey_key}'
            f')'
        )


def create_identity(
    passphrase: Optional[bytes] = None, 
    net: Net = Net.TEST,
) -> 'Identity':
    """
    Create bitcoin identity: secret key, public key, and wallet address.
    """
    sk, pk = gen_key_pair(passphrase)
    address = pk.address(net, compressed=True)
    pkb_hash = pk.encode(compressed=True, hash160=True)
    return Identity(sk, pk, address, pkb_hash)
