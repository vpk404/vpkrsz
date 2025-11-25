# rsz_add_adv.py (added SegWit BIP-143 sighash support + fixed varint)

import requests, time, os, sys, math, signal
from hashlib import sha256
from collections import defaultdict
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple

# -------------------- Config --------------------
MEMPOOL_API_TXS = "https://mempool.space/api/address/{address}/txs?limit={limit}&offset={offset}"
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # secp256k1 order

# fetch tuning
BATCH_SIZE = 25
REQ_TIMEOUT = 20
MAX_RETRIES = 10  # increased retries

# -------------------- Globals --------------------

TOTAL_ADDRESSES = 0
SCANNED_ADDRESSES = 0
VULNERABLE_ADDRESSES = 0
VULN_COUNTS = defaultdict(int)
CURRENT_ADDRESS = ""
MAX_DISPLAYED_ADDRESSES = 10
EXIT_FLAG = False
REPORTS: List[Dict[str, Any]] = []
MAX_TRANSACTIONS = 0  # 0 => no limit

# Global r map
GLOBAL_R_MAP: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
SAVED_R_GROUPS: Dict[str, List[str]] = defaultdict(list)

# HTTP session for mempool.space API
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "SafeBTCScanner-Mempool/1.5-reused-only"})

# -------------------- Signals/UI --------------------
def signal_handler(sig, frame):
    global EXIT_FLAG
    EXIT_FLAG = True
    print("\nExiting gracefully...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def clear():
    try:
        os.system('cls' if os.name == 'nt' else 'clear')
    except Exception:
        pass

def display_stats():
    clear()
    print("VPK Bitcoin RSZ Scanner")
    print(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*80)
    print(f"Total Addresses: {TOTAL_ADDRESSES}")
    print(f"Scanned Addresses: {SCANNED_ADDRESSES}")
    percent = (VULNERABLE_ADDRESSES / SCANNED_ADDRESSES * 100) if SCANNED_ADDRESSES > 0 else 0.0
    print(f"Vulnerable Addresses: {VULNERABLE_ADDRESSES} ({percent:.1f}%)")
    print("\nVulnerabilities Found (counts):")
    print(f"🔴 Reused Nonce: {VULN_COUNTS['Reused Nonce']}")
    print("="*80)
    print(f"\nCurrently Scanning: {CURRENT_ADDRESS}")
    vuln_addrs = [r['address'] for r in REPORTS if r.get('vulnerabilities')]
    print("\nRecent Vulnerable Addresses:")
    for addr in vuln_addrs[-MAX_DISPLAYED_ADDRESSES:]:
        print(f" - {addr}")
    print("="*80)

def backoff_sleep(attempt: int):
    delay = min(2 ** attempt * 3, 120)  # longer backoff with multiplier 3
    print(f"[backoff] Sleeping {delay:.1f}s (attempt {attempt})")
    time.sleep(delay)

# -------------------- Networking --------------------
def get_total_transactions(address: str) -> Optional[int]:
    attempts = 0
    while attempts < MAX_RETRIES and not EXIT_FLAG:
        try:
            url = f"https://mempool.space/api/address/{address}"
            r = SESSION.get(url, timeout=REQ_TIMEOUT)
            if r.status_code == 200:
                data = r.json()
                return data.get("chain_stats", {}).get("tx_count", 0)
            elif r.status_code == 429:
                print(f"[rate limit] Total tx for {address}, retrying...")
                attempts += 1
                backoff_sleep(attempts)
            else:
                attempts += 1
                time.sleep(2)  # increased sleep
        except Exception as e:
            print(f"[warn] get_total_transactions({address}) attempt {attempts+1}: {e}")
            attempts += 1
            time.sleep(2)
    print(f"[error] Failed to get total tx for {address} after {MAX_RETRIES} attempts")
    return None

def fetch_transactions_batch(address: str, offset: int, limit: int) -> Optional[List[dict]]:
    attempts = 0
    while attempts < MAX_RETRIES and not EXIT_FLAG:
        try:
            url = MEMPOOL_API_TXS.format(address=address, offset=offset, limit=limit)
            r = SESSION.get(url, timeout=REQ_TIMEOUT)
            if r.status_code == 200:
                return r.json()
            elif r.status_code == 429:
                print(f"[rate limit] Batch offset {offset} for {address}, retrying...")
                attempts += 1
                backoff_sleep(attempts)
            elif r.status_code in (500, 502, 503, 504):
                print(f"[server err {r.status_code}] Batch offset {offset} for {address}, retrying...")
                attempts += 1
                backoff_sleep(attempts)
            else:
                print(f"[http {r.status_code}] Batch offset {offset} for {address}, retrying...")
                attempts += 1
                time.sleep(2)  # increased sleep
        except Exception as e:
            print(f"[warn] batch offset {offset} for {address} attempt {attempts+1}: {e}")
            attempts += 1
            time.sleep(2)
    print(f"[error] failed batch after {MAX_RETRIES} attempts (offset {offset}) for {address}")
    return None

def fetch_all_transactions(address: str, max_retries: int = 3) -> List[dict]:
    for retry in range(max_retries):
        total = get_total_transactions(address)
        if total is None:
            if retry < max_retries - 1:
                print(f"[retry {retry+1}] Retrying total tx fetch for {address}")
                time.sleep(10)  # increased delay
                continue
            else:
                print(f"[fatal] Cannot get total tx for {address}, skipping")
                return []

        if total <= 0:
            return []

        print(f"\nAddress {address} has {total} total transactions")

        total_to_fetch = min(total, MAX_TRANSACTIONS) if MAX_TRANSACTIONS > 0 else total
        print(f"Fetching {total_to_fetch} transactions (attempt {retry+1})…")

        out: List[dict] = []
        offset = 0
        failed_batches = 0
        while offset < total_to_fetch and not EXIT_FLAG:
            remaining = total_to_fetch - offset
            size = min(BATCH_SIZE, remaining)
            print(f"Fetching batch {offset+1}-{offset+size} of {total_to_fetch}…")
            batch = fetch_transactions_batch(address, offset, size)
            if batch is None:
                failed_batches += 1
                print(f"[warn] Batch failed, sleeping 5s")  # increased sleep
                time.sleep(5)
                continue
            if not batch:
                break
            out.extend(batch)
            offset += len(batch)
            if offset < total_to_fetch:
                time.sleep(1.5)  # increased delay between batches

        if len(out) > 0:
            print(f"Successfully fetched {len(out)} txs for {address}")
            return out
        else:
            print(f"[warn] No txs fetched for {address} (attempt {retry+1}), retrying...")
            if retry < max_retries - 1:
                time.sleep(20)  # longer delay before full retry
                continue

    print(f"[fatal] Failed to fetch any txs for {address} after {max_retries} attempts, skipping")
    return []

# -------------------- ScriptSig parsing --------------------
def parse_der_sig_from_hex(sig_hex: str) -> Optional[Tuple[int, int, int]]:
    try:
        i = sig_hex.find("30")
        if i == -1:
            return None
        i0 = i + 2
        _seq_len = int(sig_hex[i0:i0+2], 16); i0 += 2
        if sig_hex[i0:i0+2] != "02": return None
        i0 += 2
        r_len = int(sig_hex[i0:i0+2], 16); i0 += 2
        r_hex = sig_hex[i0:i0 + 2*r_len]; i0 += 2*r_len
        if sig_hex[i0:i0+2] != "02": return None
        i0 += 2
        s_len = int(sig_hex[i0:i0+2], 16); i0 += 2
        s_hex = sig_hex[i0:i0 + 2*s_len]; i0 += 2*s_len
        sighash_hex = sig_hex[i0:i0+2]
        sighash_flag = int(sighash_hex, 16) if sighash_hex else 1
        r = int(r_hex, 16); s = int(s_hex, 16)
        return (r, s, sighash_flag)
    except Exception:
        return None

def extract_pubkey_from_scriptsig(script_hex: str) -> Optional[str]:
    import re
    hexstr = script_hex.lower()
    candidates = []
    for m in re.finditer(r'(02|03)[0-9a-f]{64}', hexstr):
        candidates.append((m.start(), m.group(0)))
    for m in re.finditer(r'04[0-9a-f]{128}', hexstr):
        candidates.append((m.start(), m.group(0)))
    if not candidates:
        return None
    candidates.sort(key=lambda x: x[0])
    return candidates[-1][1]

# -------------------- SIGHASH / preimage helpers --------------------
def varint(n: int) -> bytes:
    """Bitcoin varint serialization."""
    if n < 0xfd:
        return n.to_bytes(1, 'little')
    elif n <= 0xffff:
        return b'\xfd' + n.to_bytes(2, 'little')
    elif n <= 0xffffffff:
        return b'\xfe' + n.to_bytes(4, 'little')
    else:
        return b'\xff' + n.to_bytes(8, 'little')

def compute_legacy_sighash(tx: dict, vin_idx: int, sighash_flag: int) -> Optional[int]:
    try:
        from hashlib import sha256

        def dsha(b: bytes) -> bytes:
            return sha256(sha256(b).digest()).digest()

        version = int(tx.get("version", 1))
        locktime = int(tx.get("locktime", 0))
        ser = version.to_bytes(4, "little")

        # inputs
        vins = tx.get("vin", [])
        input_count = len(vins)
        ser += varint(input_count)
        for i, inp in enumerate(vins):
            prev_txid = inp.get("txid", "")
            if not prev_txid:
                return None
            prev_txid_bytes = bytes.fromhex(prev_txid)[::-1]
            vout_n = int(inp.get("vout", 0))
            ser += prev_txid_bytes
            ser += vout_n.to_bytes(4, "little")
            if i == vin_idx:
                prevout = inp.get("prevout", {})
                script_pubkey = prevout.get("scriptpubkey", "")
                if not script_pubkey:
                    return None
                script_bytes = bytes.fromhex(script_pubkey)
                script_len = len(script_bytes)
                ser += varint(script_len) + script_bytes
            else:
                ser += b"\x00"
            sequence = int(inp.get("sequence", 0xffffffff))
            ser += sequence.to_bytes(4, "little")

        # outputs
        vouts = tx.get("vout", [])
        output_count = len(vouts)
        ser += varint(output_count)
        for out in vouts:
            value = int(out.get("value", 0))
            ser += value.to_bytes(8, "little")
            scriptpubkey = out.get("scriptpubkey", "")
            script_bytes = bytes.fromhex(scriptpubkey)
            script_len = len(script_bytes)
            ser += varint(script_len) + script_bytes

        ser += locktime.to_bytes(4, "little")
        ser += sighash_flag.to_bytes(4, "little")

        return int.from_bytes(dsha(ser), "big")
    except Exception as e:
        print(f"[warn] compute_legacy_sighash error: {e}")
        return None

def compute_bip143_sighash(tx: dict, vin_idx: int, sighash_flag: int) -> Optional[int]:
    try:
        from hashlib import sha256

        def dsha(b: bytes) -> bytes:
            return sha256(sha256(b).digest()).digest()

        vins = tx.get("vin", [])
        txin = vins[vin_idx]
        prevout = txin.get("prevout", {})
        input_type = prevout.get("type", "unknown")

        if input_type not in ["p2wpkh", "p2sh-p2wpkh"]:
            print(f"[warn] Unsupported BIP143 type: {input_type}")
            return None

        version = int(tx.get("version", 2))
        locktime = int(tx.get("locktime", 0))

        # hashPrevouts
        prevouts_ser = b""
        for inp in vins:
            prev_txid_bytes = bytes.fromhex(inp.get("txid", ""))[::-1]
            vout_n = int(inp.get("vout", 0))
            prevouts_ser += prev_txid_bytes + vout_n.to_bytes(4, "little")
        hashPrevouts = dsha(prevouts_ser)

        # hashSequence
        sequences_ser = b""
        for inp in vins:
            sequence = int(inp.get("sequence", 0xffffffff))
            sequences_ser += sequence.to_bytes(4, "little")
        hashSequence = dsha(sequences_ser)

        # hashOutputs
        outputs_ser = b""
        for out in tx.get("vout", []):
            value = int(out.get("value", 0))
            outputs_ser += value.to_bytes(8, "little")
            scriptpubkey = out.get("scriptpubkey", "")
            script_bytes = bytes.fromhex(scriptpubkey)
            script_len = len(script_bytes)
            outputs_ser += varint(script_len) + script_bytes
        hashOutputs = dsha(outputs_ser)

        # outpoint
        outpoint = bytes.fromhex(txin.get("txid", ""))[::-1] + int(txin.get("vout", 0)).to_bytes(4, "little")

        # scriptCode
        if input_type == "p2wpkh":
            spk_hex = prevout.get("scriptpubkey", "")
            spk_bytes = bytes.fromhex(spk_hex)
            if len(spk_bytes) != 22 or spk_bytes[:2] != b'\x00\x14':
                return None
            hash160 = spk_bytes[2:]
        elif input_type == "p2sh-p2wpkh":
            scriptsig = txin.get("scriptsig", {})
            sigscript_hex = scriptsig.get("hex", "") if isinstance(scriptsig, dict) else ""
            if not sigscript_hex:
                return None
            # sigscript_hex starts with push len (16 for 22 bytes) + 0014{20 bytes hex}
            if len(sigscript_hex) != 44:  # 2 + 40
                return None
            push_len_hex = sigscript_hex[:2]
            if int(push_len_hex, 16) != 22:
                return None
            redeem_hex = sigscript_hex[2:]
            redeem_bytes = bytes.fromhex(redeem_hex)
            if len(redeem_bytes) != 22 or redeem_bytes[:2] != b'\x00\x14':
                return None
            hash160 = redeem_bytes[2:]
        else:
            return None

        scriptCode = b"\x76\xa9\x14" + hash160 + b"\x88\xac"

        value = int(prevout.get("value", 0)).to_bytes(8, "little")
        sequence = int(txin.get("sequence", 0xffffffff)).to_bytes(4, "little")

        preimage = (
            version.to_bytes(4, "little") +
            hashPrevouts +
            hashSequence +
            outpoint +
            scriptCode +
            value +
            sequence +
            hashOutputs +
            locktime.to_bytes(4, "little") +
            sighash_flag.to_bytes(4, "little")
        )

        return int.from_bytes(dsha(preimage), "big")
    except Exception as e:
        print(f"[warn] compute_bip143_sighash error: {e}")
        return None

def compute_sighash_z(tx: dict, vin_idx: int, sighash_flag: int) -> Optional[int]:
    """
    Compute real ECDSA message hash (z) for tx input vin_idx.
    Supports legacy and BIP-143 (P2WPKH/P2SH-P2WPKH).
    """
    try:
        if sighash_flag != 1:
            print(f"[warn] Non-SIGHASH_ALL ({sighash_flag}), skipping z computation")
            return None

        vins = tx.get("vin", [])
        if vin_idx >= len(vins):
            return None
        txin = vins[vin_idx]
        prevout = txin.get("prevout", {})
        input_type = prevout.get("type", "unknown")

        if input_type in ["p2wpkh", "p2sh-p2wpkh"]:
            return compute_bip143_sighash(tx, vin_idx, sighash_flag)
        else:
            # legacy (p2pkh, etc.)
            return compute_legacy_sighash(tx, vin_idx, sighash_flag)
    except Exception as e:
        print(f"[warn] compute_sighash_z error: {e}")
        return None

def extract_signatures(transactions: List[dict]) -> List[Dict[str, Any]]:
    """
    Extract r, s, pubkey, sighash, and compute original z (message hash)
    from transaction data. Supports legacy and SegWit (P2WPKH/P2SH-P2WPKH).
    """
    sigs = []
    for tx in transactions:
        try:
            txid = tx.get("txid", "")
            vins = tx.get("vin", [])

            for vin_idx, txin in enumerate(vins):
                parsed = None
                pubkey = None
                sighash_flag = 1

                witness = txin.get("witness", [])
                if witness:
                    # SegWit
                    if len(witness) >= 2:
                        sig_hex = witness[0]
                        pubkey = witness[1]
                        parsed = parse_der_sig_from_hex(sig_hex)
                else:
                    # Legacy
                    scriptsig = txin.get("scriptsig", {})
                    script_hex = scriptsig.get("hex", "") if isinstance(scriptsig, dict) else txin.get("scriptsig", "")
                    if script_hex:
                        pubkey = extract_pubkey_from_scriptsig(script_hex)
                        parsed = parse_der_sig_from_hex(script_hex)  # Reuse for legacy too, as it finds the DER

                if not parsed:
                    continue

                r, s, sighash_flag = parsed

                # Compute real z
                z_val = compute_sighash_z(tx, vin_idx, sighash_flag)

                sigs.append({
                    "txid": txid,
                    "vin": vin_idx,
                    "r": r,
                    "s": s,
                    "sighash": sighash_flag,
                    "pubkey": pubkey,
                    "z_original": z_val
                })
        except Exception as e:
            print(f"[warn] extract_signatures error: {e}")
            continue

    return sigs

# -------------------- Analyses --------------------
def check_reused_nonce_global(this_address: str, signatures: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    results = []
    seen_r_local = set()
    for s in signatures:
        r_val = s["r"]
        if r_val in seen_r_local:
            continue
        seen_r_local.add(r_val)
        group = GLOBAL_R_MAP.get(r_val, [])
        if len(group) >= 2:
            occ = []
            seen = set()
            for item in group:
                txid = item.get("txid", "")
                pk = item.get("pubkey")
                key = (txid, pk)
                if key in seen:
                    continue
                seen.add(key)
                occ.append({"txid": txid, "pubkey": pk})
            if len(occ) >= 2:
                results.append({
                    "type": "Reused Nonce",
                    "r": hex(r_val),
                    "occurrences": occ,
                    "risk": "Multiple signatures share identical r (strong vulnerability).",
                    "action": "Rotate keys; cease signing with affected key. Investigate wallet RNG."
                })
    return results

# -------------------- Reporting --------------------
def save_rnonce(vulns: List[Dict[str, Any]], address: str):
    if not vulns:
        return
    for v in vulns:
        if v["type"] != "Reused Nonce":
            continue
        r_hex = v["r"][2:] if isinstance(v.get("r"), str) and v["r"].startswith("0x") else str(hex(int(v.get("r")))[2:])
        for occ in v["occurrences"]:
            txid = occ.get("txid") or "N/A"
            pk = occ.get("pubkey") or "N/A"
            key = f"{txid}|{pk}"
            if key not in SAVED_R_GROUPS[r_hex]:
                SAVED_R_GROUPS[r_hex].append(key)

    os.makedirs("reports", exist_ok=True)
    path_rnonce = os.path.join("reports", "rnonce.txt")
    with open(path_rnonce, "w", encoding="utf-8") as f:
        for r_hex, occ_list in SAVED_R_GROUPS.items():
            f.write("=" * 80 + "\n")
            f.write("Reused Nonce Group\n")
            f.write("=" * 80 + "\n")
            f.write(f"r: {r_hex}\n")
            f.write("Occurrences:\n")
            for key in occ_list:
                txid, pk = key.split("|")
                f.write(f" - txid={txid} pubkey={pk}\n")
            f.write("\n")
    print(f"[updated] rnonce groups saved → {path_rnonce}")

    # Save rnon.txt with s, z, pubkey in hex
    path_rnon = os.path.join("reports", "rnon.txt")
    with open(path_rnon, "w", encoding="utf-8") as f:
        for r_hex, _ in list(SAVED_R_GROUPS.items()):
            r_int = int(r_hex, 16)
            group = GLOBAL_R_MAP.get(r_int, [])
            if len(group) < 2:
                continue
            f.write("=" * 80 + "\n")
            f.write("Reused Nonce Group\n")
            f.write("=" * 80 + "\n")
            f.write(f"r: {r_hex}\n")
            f.write("Occurrences:\n")
            seen = set()
            for item in group:
                txid = item.get("txid", "N/A")
                s_val = item.get("s", "N/A")
                if isinstance(s_val, int):
                    s_hex = hex(s_val)[2:]
                else:
                    s_hex = str(s_val)
                z_val = item.get("z_original")
                z_hex = hex(z_val)[2:] if z_val is not None else "N/A"
                pk = item.get("pubkey", "N/A")
                key = (txid, pk)
                if key in seen:
                    continue
                seen.add(key)
                f.write(f" - txid={txid} s={s_hex} z={z_hex} pubkey={pk}\n")
            f.write("\n")
    print(f"[updated] rnon groups saved → {path_rnon}")

# -------------------- Driver --------------------

def analyze_address(address: str) -> Optional[Dict[str, Any]]:
    global SCANNED_ADDRESSES, VULNERABLE_ADDRESSES, CURRENT_ADDRESS

    CURRENT_ADDRESS = address
    SCANNED_ADDRESSES += 1
    display_stats()

    report: Dict[str, Any] = {
        "address": address,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "transaction_count": 0,
        "signature_count": 0,
        "vulnerabilities": [],
    }

    # fetch all transactions with retries
    txs = fetch_all_transactions(address)
    report["transaction_count"] = len(txs)

    # extract signatures
    sigs = extract_signatures(txs)
    report["signature_count"] = len(sigs)
    print(f"Extracted {len(sigs)} signatures from {len(txs)} txs")

    # push to GLOBAL_R_MAP
    for g in sigs:
        GLOBAL_R_MAP[g["r"]].append({
            "address": address,
            "txid": g.get("txid", ""),
            "pubkey": g.get("pubkey"),
            "s": g["s"],
            "z_original": g["z_original"]
        })

    vulns: List[Dict[str, Any]] = []

    # Reused nonce check
    reused = check_reused_nonce_global(address, sigs)
    if reused:
        vulns.extend(reused)
        VULN_COUNTS["Reused Nonce"] += len(reused)
        print(f"Found {len(reused)} reused nonce groups for {address}")

    # Mark vulnerable
    if vulns:
        VULNERABLE_ADDRESSES += 1
        report["vulnerabilities"] = vulns

    REPORTS.append(report)

    # Save rnonce and rnon
    save_rnonce(vulns, address)

    # Increased delay between addresses to respect rate limits
    print(f"[delay] 3s pause after {address}")
    time.sleep(3)

    return report

def get_input_file() -> str:
    while True:
        file_name = input("Enter path to BTC addresses file (one per line): ").strip()
        if os.path.isfile(file_name):
            return file_name
        print(f"File not found: {file_name}. Try again.")

def get_transaction_limit() -> int:
    while True:
        s = input("Max transactions per address (0 = no limit): ").strip()
        try:
            v = int(s)
            if v >= 0:
                return v
        except ValueError:
            pass
        print("Please enter a valid non-negative integer.")

def main():
    global TOTAL_ADDRESSES, MAX_TRANSACTIONS
    try:
        addr_file = get_input_file()
        MAX_TRANSACTIONS = get_transaction_limit()
        with open(addr_file, "r", encoding="utf-8") as f:
            addresses = [ln.strip() for ln in f if ln.strip()]
        TOTAL_ADDRESSES = len(addresses)

        print("\nAll transaction data will be fetched for reused nonce checks.")
        print("Improved rate limit handling: retries, backoffs, and increased delays.")

        for addr in addresses:
            if EXIT_FLAG:
                break
            analyze_address(addr)

        if not EXIT_FLAG:
            print("\nScanning completed!")
            print(f"Final: {VULNERABLE_ADDRESSES}/{TOTAL_ADDRESSES} addresses show risk signals")
            print("\nVulnerable Addresses:")
            for rep in REPORTS:
                if rep.get("vulnerabilities"):
                    print(f" - {rep['address']}")
            print("\nReused nonce groups saved in 'reports/rnonce.txt' and 'reports/rnon.txt'.")
    except KeyboardInterrupt:
        sys.exit(0)

if __name__ == "__main__":
    main()
