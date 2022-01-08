"""
Core functions for math over Elliptic Curves over Finite Fields,
especially the ability to define Points on Curves and perform
addition and scalar multiplication.
"""

from dataclasses import dataclass
import math
import random
from timeit import timeit

# -----------------------------------------------------------------------------
# public API

__all__ = ['Curve', 'Point', 'Generator']

# -----------------------------------------------------------------------------


def extended_euclidean_algorithm(a, b):
    """
    Returns (gcd, x, y) s.t. a * x + b * y == gcd
    This function implements the extended Euclidean algorithm and runs in O(log b) 
    in the worst case, taken from Wikipedia.
    """
    r0, r1 = a, b
    s0, s1 = 1, 0
    t0, t1 = 0, 1
    while r1 != 0:
        q = r0 // r1
        r1, r0 = r0 - r1 * q, r1
        s1, s0 = s0 - s1 * q, s1
        t1, t0 = t0 - t1 * q, t1
    return r0, s0, t0


@dataclass
class Curve:
    """
    Elliptic Curve over the field of integers modulo a prime.
    Points on the curve satisfy y^2 = x^3 + a*x + b (mod p).
    """
    p: int  # the prime modulus of the finite field
    a: int
    b: int
    
    def point_is_on_curve(self, x: int, y: int) -> bool:
        return (y**2 - x**3 - 7) % self.p == 0


def inv(n, p):
    """ 
    returns modular multiplicate inverse m s.t. (n * m) % p == 1
    """
    gcd, x, y = extended_euclidean_algorithm(n, p)  # pylint: disable=unused-variable
    return x % p


@dataclass
class Point:
    """ An integer point (x,y) on a Curve """
    curve: Curve
    x: int
    y: int
    
    def is_on_curve(self) -> bool:
        return self.curve.point_is_on_curve(self.x, self.y)

    def __add__(self, other) -> 'Point':
        """
        Elliptic curve additi9on
        """
        # handle special case of P + 0 = 0 + P = 0
        if self == INF: 
            return other
        if other == INF:
            return self
        # handle special case of P + (-P) = 0
        if self.x == other.x and self.y != other.y: 
            return INF
        # compute the "slope"
        if self.x == other.x:  # (self.y = other.y is guaranteed too per above check)
            m = (3 * self.x**2 + self.curve.a) * inv(2 * self.y, self.curve.p)
        else:
            m = (self.y - other.y) * inv(self.x - other.x, self.curve.p)
        # compute the new point
        rx = (m**2 - self.x - other.x) % self.curve.p
        ry = (-(m*(rx - self.x) + self.y)) % self.curve.p
        return Point(self.curve, rx, ry)

    def __rmul__(self, k: int) -> 'Point':
        """
        Double-and-add.
        
        We’d have to add G to itself a very large number (=secret key) of times, because 
        the secret key is a large integer. So the result would be correct but it would run 
        very slow. Instead, let’s implement the “double and add” algorithm to dramatically 
        speed up the repeated addition.
        """
        assert isinstance(k, int) and k >= 0
        result = INF
        append = self
        while k:
            if k & 1:
                result += append
            append += append
            k >>= 1
        return result


INF = Point(None, None, None)  # special point at "infinity", kind of like a zero


@dataclass
class Generator:
    """
    A generator over a curve: an initial point and the (pre-computed) order
    """
    G: Point     # a generator point on the curve
    n: int       # the order of the generating point, so 0*G = n*G = INF


# print(euclidean_algorithm(240, 46))
# a, b = 240, 46
# a, b = max(a, b), min(a, b)
# r, s, t = extended_euclidean_algorithm(a, b)
# print(f'{a=}, {b=}, {r=}, {s=}, {t=}, {a*s+b*t=}')

# 21*51, 21*22
# 1071/51=21 + 462/22=21 = 21


def test_gcd(n=100):
    for i in range(n):
        a, b = random.randint(0, 1000), random.randint(0, 1000)
        mine, _, _ = extended_euclidean_algorithm(a, b)
        standard = math.gcd(a, b)
        if mine != standard:
            print(f'{a=}, {b=}, {mine=}, {standard=}')
            
            
def benchmark_gcd():
    print(timeit("""\
for i in range(1000):
    a, b = random.randint(0, 100000), random.randint(0, 100000)
    c = euclidean_algorithm(a, b)
""", setup="""\
import random
from __main__ import euclidean_algorithm
""", number=1000))

    print(timeit("""\
for i in range(1000):
    a, b = random.randint(0, 100000), random.randint(0, 100000)
    c = math.gcd(a, b)
""", setup="""\
import random
import math
""", number=1000))
