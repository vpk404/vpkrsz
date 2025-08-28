# -*- coding: utf-8 -*-
"""
@author: iceland
@credit: KV
"""
import random
import secp256k1 as ice

G = ice.scalar_multiplication(1)
N = ice.N

# ==============================================================================

def inv(a):
    return pow(a, N - 2, N)


def valid_rsz(r, s, z, pub_point):
    RP1 = ice.pub2upub('02' + hex(r)[2:].zfill(64))
    RP2 = ice.pub2upub('03' + hex(r)[2:].zfill(64))
    sdr = (s * inv(r)) % N
    zdr = (z * inv(r)) % N
    FF1 = ice.point_subtraction( ice.point_multiplication(RP1, sdr),
                                ice.scalar_multiplication(zdr) )
    FF2 = ice.point_subtraction( ice.point_multiplication(RP2, sdr),
                                ice.scalar_multiplication(zdr) )
    if FF1 == pub_point or FF2 == pub_point:
        return True
    else:
        return False


def getk1(r1, s1, z1, r2, s2, z2, m):
    nr = (s2 * m * r1 + z1 * r2 - z2 * r1) % N
    dr = (s1 * r2 - s2 * r1) % N
    return (nr * inv(dr)) % N


def getpvk(r1, s1, z1, r2, s2, z2, m):
    x1 = (s2 * z1 - s1 * z2 + m * s1 * s2) % N
    xi = inv((s1 * r2 - s2 * r1) % N)
    x = (x1 * xi) % N
    return x

def getx(Q):
    return int(Q[1:33].hex(), 16)
# ==============================================================================

# keep a (dummy) private key here only to demonstrate valid_rsz check;
# in real recovery you don't need pvk beforehand. We keep it to compute Q for validation.
pvk = random.SystemRandom().randint(1, 2 ** 256)
print('=' * 72)
print('  (Demo) True Privatekey (random, not the recovered one) = ', hex(pvk))
print('=' * 72)
Q = ice.scalar_multiplication(pvk)

# -------------------------
# ===  REPLACED VALUES  ===
# Put your real R, S, Z hex values here (they are already filled)
# -------------------------
r_hex = "538d2959108c11f0a34dd65c084af69765c66988b04e09eb0eebb7be69dde951"
s1_hex = "fb7109b5c67ab0f10d63c1123554ce766bb69e370f360827bbfa058e17efb37"
z1_hex = "4b4b30a07d1c07a340916b0b8a7294de61c92fa2dabf0f4d9ce62a299e20f6ba"

# second signature (same R)
s2_hex = "c1ad3ba1a090b8ad553545b51be4986ab6cc408f4d9ff461a4f188121f92074"
z2_hex = "21440dd4fbc7e00f06b01ce0e0094f79281b594ae9ec450180ebab15169a0b36"

# convert to ints
r1 = int(r_hex, 16)
r2 = r1
s1 = int(s1_hex, 16)
s2 = int(s2_hex, 16)
z1 = int(z1_hex, 16)
z2 = int(z2_hex, 16)

# We don't know original k1,k2; because R is same we assume same nonce -> diff = 0
diff = 0
# ==============================================================================

print(f' (input) r1: {hex(r1)}\ns1: {hex(s1)}\nz1: {hex(z1)}')
if valid_rsz(r1, s1, z1, Q): print('  Tx1 Correct: rsz Validated the Pubkey (with demo Q)')
print('=' * 72)
print(f' (input) r2: {hex(r2)}\ns2: {hex(s2)}\nz2: {hex(z2)}')
if valid_rsz(r2, s2, z2, Q): print('  Tx2 Correct: rsz Validated the Pubkey (with demo Q)')

# ==============================================================================

print('=' * 72)
print('  Starting to solve rsz using difference of k between 2 Tx (assuming same nonce)')
k = getk1(r1, s1, z1, r2, s2, z2, diff)
x = getpvk(r1, s1, z1, r2, s2, z2, diff)
print(f'  Extracted Privatekey (x) = {hex(x)}')
print(f'  Extracted Nonce (k) = {hex(k)}')

# verify that k produces r (optional check)
try:
    if getx(ice.scalar_multiplication(k)) == r1 or getx(ice.scalar_multiplication(k)) == r2:
        print(f'====   Nonce Found using 2 rsz diff   = {hex(k)}')
    else:
        print('Nonce k does NOT produce provided R (r mismatch).')
except Exception as e:
    print('Could not validate nonce ->', e)

print('=' * 72)
