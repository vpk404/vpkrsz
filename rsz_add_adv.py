# btc_safe_scanner_txt_only_v3.py
# SAFE MODE: Reporting-only.
# - Reused Nonce => show r, s, z_txid_sha256 per occurrence (z surrogate, NOT real ECDSA z)
# - Save only TXT
# - NEW: Save "K-Value Signals" reports ONLY if signatures >= MIN_SIGS_FOR_KVALUE_SAVE AND evidence strong
# - NEW: Deep Analyse section + per-address vulnerability counts
# - NEW: Cross-address reused-r detection + consolidated summary

import requests
import time
from hashlib import sha256
import os
from collections import defaultdict, Counter
from datetime import datetime
import signal
import sys
import math
from typing import List, Dict, Any, Optional, Tuple

# -------------------- Config --------------------
BLOCKCHAIN_API = "https://blockchain.info/address/{address}?format=json&offset={offset}&limit={limit}"
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # secp256k1 order

# "बड़ी" K-Value रिपोर्ट तभी सेव करो जब signatures कम-से-कम इतने हों:
MIN_SIGS_FOR_KVALUE_SAVE = 20

# fetch tuning
BATCH_SIZE = 100
REQ_TIMEOUT = 20
MAX_RETRIES = 5

# throttle
def backoff_sleep(attempt: int):
    delay = min(2 ** attempt, 30)
    time.sleep(delay + (0.25 * attempt))

# -------------------- Globals --------------------
TOTAL_ADDRESSES = 0
SCANNED_ADDRESSES = 0
VULNERABLE_ADDRESSES = 0
VULN_COUNTS = defaultdict(int)  # per run totals
CURRENT_ADDRESS = ""
MAX_DISPLAYED_ADDRESSES = 10
EXIT_FLAG = False
REPORTS: List[Dict[str, Any]] = []
MAX_TRANSACTIONS = 0  # 0 => no limit

# Global r -> list of occurrences across ALL addresses
GLOBAL_R_MAP: Dict[int, List[Dict[str, Any]]] = defaultdict(list)

# Track reused-nonce groups (all occurrences memory में रहेंगे)
# key = r_hex string, value = list of "txid|pubkey" strings
SAVED_R_GROUPS: Dict[str, List[str]] = defaultdict(list)

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "SafeBTCScanner-TXT/1.4-crossaddr"})


# -------------------- Signals --------------------
def signal_handler(sig, frame):
    global EXIT_FLAG
    EXIT_FLAG = True
    print("\nExiting gracefully...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# -------------------- UI helpers --------------------
def clear():
    try:
        os.system('cls' if os.name == 'nt' else 'clear')
    except Exception:
        pass

def display_stats():
    clear()
    print("CRYPTOGRAPHYTUBE Bitcoin Vulnerability Scanner (SAFE MODE, TXT only)")
    print(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*80)
    print(f"Total Addresses: {TOTAL_ADDRESSES}")
    print(f"Scanned Addresses: {SCANNED_ADDRESSES}")
    percent = (VULNERABLE_ADDRESSES / SCANNED_ADDRESSES * 100) if SCANNED_ADDRESSES > 0 else 0.0
    print(f"Vulnerable Addresses: {VULNERABLE_ADDRESSES} ({percent:.1f}%)")
    print("\nVulnerabilities Found (counts):")
    for key in ["Reused Nonce", "Weak RNG", "Multi-Nonce Delta", "K-Value Signals"]:
        print(f"🔴 {key}: {VULN_COUNTS[key]}")
    print("="*80)
    print(f"\nCurrently Scanning: {CURRENT_ADDRESS}")
    vuln_addrs = [r['address'] for r in REPORTS if r.get('vulnerabilities')]
    print("\nRecent Vulnerable Addresses:")
    for addr in vuln_addrs[-MAX_DISPLAYED_ADDRESSES:]:
        print(f" - {addr}")
    print("="*80)

# -------------------- Networking --------------------
def get_total_transactions(address: str) -> int:
    try:
        url = f"https://blockchain.info/address/{address}?format=json"
        r = SESSION.get(url, timeout=15)
        if r.status_code == 200:
            data = r.json()
            return int(data.get('n_tx', 0))
    except Exception as e:
        print(f"[warn] get_total_transactions({address}) -> {e}")
    return 0

def fetch_transactions_batch(address: str, offset: int, limit: int) -> Optional[List[dict]]:
    attempts = 0
    while attempts < MAX_RETRIES and not EXIT_FLAG:
        try:
            url = BLOCKCHAIN_API.format(address=address, offset=offset, limit=limit)
            r = SESSION.get(url, timeout=REQ_TIMEOUT)
            if r.status_code == 200:
                return r.json().get('txs', [])
            if r.status_code in (429, 500, 502, 503, 504):
                print(f"[rate/err {r.status_code}] waiting…")
                attempts += 1
                backoff_sleep(attempts)
            else:
                attempts += 1
                backoff_sleep(attempts)
        except Exception as e:
            print(f"[warn] batch offset {offset}: {e}")
            attempts += 1
            backoff_sleep(attempts)
    print(f"[error] failed batch after {attempts} attempts (offset {offset})")
    return None

def fetch_all_transactions(address: str) -> List[dict]:
    total = get_total_transactions(address)
    if total <= 0:
        return []
    print(f"\nAddress {address} has {total} total transactions")

    total_to_fetch = min(total, MAX_TRANSACTIONS) if MAX_TRANSACTIONS > 0 else total
    print(f"Fetching {total_to_fetch} transactions…")

    out: List[dict] = []
    offset = 0
    while offset < total_to_fetch and not EXIT_FLAG:
        remaining = total_to_fetch - offset
        size = min(BATCH_SIZE, remaining)
        print(f"Fetching {offset+1}-{offset+size} of {total_to_fetch}…")
        batch = fetch_transactions_batch(address, offset, size)
        if batch is None:
            time.sleep(1.0)
            continue
        if not batch:
            break
        out.extend(batch)
        offset += len(batch)
        if offset < total_to_fetch:
            time.sleep(0.3)
    return out

# -------------------- DER signature parsing --------------------
def parse_der_sig_from_scriptsig(script_hex: str) -> Optional[Tuple[int, int, int]]:
    try:
        i = script_hex.find("30")
        if i == -1:
            return None
        i0 = i
        i0 += 2
        _seq_len = int(script_hex[i0:i0+2], 16); i0 += 2

        if script_hex[i0:i0+2] != "02":
            return None
        i0 += 2
        r_len = int(script_hex[i0:i0+2], 16); i0 += 2
        r_hex = script_hex[i0:i0 + 2*r_len]; i0 += 2*r_len

        if script_hex[i0:i0+2] != "02":
            return None
        i0 += 2
        s_len = int(script_hex[i0:i0+2], 16); i0 += 2
        s_hex = script_hex[i0:i0 + 2*s_len]; i0 += 2*s_len

        sighash_hex = script_hex[i0:i0+2]
        sighash_flag = int(sighash_hex, 16) if sighash_hex else 1

        r = int(r_hex, 16)
        s = int(s_hex, 16)
        return (r, s, sighash_flag)
    except Exception:
        return None

def extract_pubkey_from_scriptsig(script_hex: str) -> Optional[str]:
    """
    Try to extract pubkey from scriptSig (P2PKH).
    Pubkeys are usually 33-byte (02/03 + 32) or 65-byte (04 + 64).
    """
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

def extract_signatures(transactions: List[dict]) -> List[Dict[str, Any]]:
    sigs = []
    for tx in transactions:
        try:
            inputs = tx.get("inputs", [])
            txid = tx.get("hash", "")
            z_txid_sha256: Optional[int] = None
            try:
                if txid and all(c in "0123456789abcdef" for c in txid.lower()):
                    z_txid_sha256 = int(sha256(bytes.fromhex(txid)).hexdigest(), 16)
            except Exception:
                z_txid_sha256 = None

            for vin_idx, txin in enumerate(inputs):
                script = txin.get("script", "")
                pubkey = extract_pubkey_from_scriptsig(script)

                parsed = parse_der_sig_from_scriptsig(script)
                if not parsed:
                    continue
                r, s, sighash_flag = parsed
                sigs.append({
                    "txid": txid,
                    "vin": vin_idx,
                    "r": r,
                    "s": s,
                    "sighash": sighash_flag,
                    "script_len": len(script)//2,
                    "pubkey": pubkey,
                    "z_txid_sha256": z_txid_sha256
                })
        except Exception as e:
            print(f"[warn] extract_signatures: {e}")
            continue
    return sigs

# -------------------- Analyses --------------------
def check_reused_nonce_global(this_address: str, signatures: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Use GLOBAL_R_MAP to report reused r groups that intersect this_address.
    Duplicate (txid, pubkey) entries को remove करता है।
    Address अब occurrences में save नहीं होगा।
    """
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
            seen = set()  # duplicates filter

            for item in group:
                txid = item.get("txid", "")
                pk = item.get("pubkey")

                key = (txid, pk)
                if key in seen:
                    continue
                seen.add(key)

                occ.append({
                    "txid": txid,
                    "pubkey": pk
                })

            # अगर unique occurrences कम से कम 2 हैं तभी vulnerability रिपोर्ट करें
            if len(occ) >= 2:
                results.append({
                    "type": "Reused Nonce",
                    "r": hex(r_val),
                    "occurrences": occ,
                    "risk": "Multiple signatures share identical r (strong vulnerability).",
                    "action": "Rotate keys; cease signing with affected key. Investigate wallet RNG.",
                    "note": "z shown is SHA256(txid) surrogate, NOT the real ECDSA preimage hash."
                })
    return results

def check_weak_rng(signatures: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if len(signatures) < 8:
        return None
    r_values = [s['r'] for s in signatures]
    unique_r = len(set(r_values))
    ratio = unique_r / len(r_values)
    if ratio < 0.6:
        return {
            "type": "Weak RNG",
            "unique_r": unique_r,
            "total": len(r_values),
            "ratio": ratio,
            "signal": "Low r diversity across signatures.",
            "note": "Heuristic signal; confirm RNG health."
        }
    return None

def check_multi_nonce_delta(signatures: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if len(signatures) < 12:
        return None
    r_vals = [s["r"] for s in signatures]
    deltas = [abs(r_vals[i] - r_vals[i-1]) for i in range(1, len(r_vals))]
    if not deltas:
        return None
    uniq = len(set(deltas))
    ratio = uniq / len(deltas)
    if ratio < 0.35:
        return {
            "type": "Multi-Nonce Delta",
            "unique_deltas": uniq,
            "total_deltas": len(deltas),
            "ratio": ratio,
            "signal": "Structured spacing in r suggests nonce patterning.",
        }
    return None

def check_kvalue_signals(signatures: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    s_vals = [s.get("s") for s in signatures if isinstance(s.get("s"), int)]
    n = len(s_vals)
    if n < MIN_SIGS_FOR_KVALUE_SAVE:
        return None

    s_sorted = sorted(s_vals)
    med = s_sorted[n // 2]
    hi = sum(1 for x in s_vals if x > med)
    lo = n - hi
    bias = abs(hi - lo) / n if n > 0 else 0.0

    gcd_all = 0
    for x in s_vals:
        gcd_all = math.gcd(gcd_all, x)
        if gcd_all == 1:
            break

    notes = []
    if bias > 0.30:
        notes.append("Non-uniform s distribution (heuristic).")
    if gcd_all > 1:
        notes.append(f"s values share a common factor {gcd_all} (heuristic signal).")

    if not notes:
        return None

    return {
        "type": "K-Value Signals",
        "notes": notes,
        "disclaimer": "Signals are heuristic and NOT a key-recovery. Review RNG & signer.",
        "gcd": (gcd_all if gcd_all > 1 else None),
        "bias": bias,
        "sample_size": n,
        "evidence_level": "strong"
    }

# -------------------- Deep analysis --------------------
def deep_analyse(signatures: List[Dict[str, Any]]) -> Dict[str, Any]:
    stats: Dict[str, Any] = {}
    total = len(signatures)
    stats["total_signatures"] = total
    if total == 0:
        return stats

    r_vals = [s["r"] for s in signatures]
    s_vals = [s["s"] for s in signatures]
    sighashes = [s.get("sighash", 1) for s in signatures]

    stats["unique_r"] = len(set(r_vals))
    stats["repeated_r_count"] = total - stats["unique_r"]

    r_counts = Counter(r_vals)
    top_r = r_counts.most_common(5)
    stats["top_r"] = [{"r": hex(r), "count": c} for (r, c) in top_r if c > 1]

    sh_counts = Counter(sighashes)
    stats["sighash_distribution"] = [{"flag": k, "count": v} for k, v in sorted(sh_counts.items())]

    s_sorted = sorted(s_vals)
    s_median = s_sorted[len(s_sorted)//2]
    stats["s_median_hex"] = hex(s_median)
    low_s = sum(1 for x in s_vals if x <= N//2)
    high_s = total - low_s
    stats["low_s_fraction"] = round(low_s / total, 4)
    stats["high_s_fraction"] = round(high_s / total, 4)

    gcd_all = 0
    for x in s_vals:
        gcd_all = math.gcd(gcd_all, x)
        if gcd_all == 1:
            break
    stats["gcd_s"] = gcd_all

    bits = [s.bit_length() for s in s_vals]
    bits_sorted = sorted(bits)
    stats["s_bits_min"] = min(bits)
    stats["s_bits_med"] = bits_sorted[len(bits_sorted)//2]
    stats["s_bits_max"] = max(bits)

    return stats

# -------------------- Reporting --------------------
def save_report_txt(address: str, report: Dict[str, Any]) -> bool:
    os.makedirs("reports", exist_ok=True)

    if not report.get("vulnerabilities"):
        print(f"[skip] {address}: clean (no anomalies)")
        return False

    vulns = report.get("vulnerabilities", [])

    # --- Only save strong K-Value reports ---
    only_kvalue = (len(vulns) == 1 and vulns[0].get("type") == "K-Value Signals")
    if only_kvalue:
        ksig = vulns[0]
        level = ksig.get("evidence_level", "weak")
        sample = ksig.get("sample_size", 0)
        if not (level == "strong" and sample >= MIN_SIGS_FOR_KVALUE_SAVE):
            print(f"[skip] {address}: K-Value evidence not strong (level={level}, n={sample})")
            return False

    txt_path = os.path.join("reports", f"{address}_report.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("CRYPTOGRAPHYTUBE Bitcoin Vulnerability Report (SAFE MODE)\n")
        f.write("=" * 80 + "\n")
        f.write(f"Scan Time: {report['scan_time']}\n")
        f.write(f"Address: {address}\n")
        f.write(f"Total Transactions: {report.get('transaction_count', 0)}\n")
        f.write(f"Signatures Analyzed: {report.get('signature_count', 0)}\n")
        f.write("=" * 80 + "\n\n")

        for i, v in enumerate(vulns, 1):
            f.write(f"🔴 VULNERABILITY #{i}: {v['type']}\n")
            f.write("-" * 80 + "\n")

            if v["type"] == "Reused Nonce":
                try:
                    r_no0x = v["r"][2:] if isinstance(v.get("r"), str) and v["r"].startswith("0x") else str(v.get("r"))
                except Exception:
                    r_no0x = str(v.get("r"))
                f.write(f"r: {r_no0x}\n")
                f.write(f"{v['risk']}\n")
                f.write("Occurrences:\n")
                for j, occ in enumerate(v["occurrences"], 1):
                    pk = occ.get("pubkey") or "N/A"
                    f.write(f" {j}. txid={occ['txid']} pubkey={pk}\n")
                f.write(f"Action: {v['action']}\n")
                f.write(f"Note: {v.get('note','')}\n")

            elif v["type"] == "Weak RNG":
                f.write(f"Unique r: {v['unique_r']}/{v['total']}  "
                        f"(ratio={v['ratio']:.2f})\n")
                f.write(f"Signal: {v['signal']}\n")
                f.write(f"Note: {v['note']}\n")

            elif v["type"] == "Multi-Nonce Delta":
                f.write(f"Unique deltas: {v['unique_deltas']}/{v['total_deltas']}  "
                        f"(ratio={v['ratio']:.2f})\n")
                f.write(f"Signal: {v['signal']}\n")

            elif v["type"] == "K-Value Signals":
                f.write(f"Evidence level: {v.get('evidence_level','unknown')}  (n={v.get('sample_size','?')})\n")
                f.write("Signals:\n")
                for note in v.get("notes", []):
                    f.write(f" - {note}\n")
                if v.get("gcd"):
                    f.write(f"GCD(s): {v['gcd']}\n")
                f.write(f"Bias (median split): {v.get('bias',0):.3f}\n")
                f.write(f"Disclaimer: {v.get('disclaimer','')}\n")

            f.write("\n")

        da = report.get("deep_analysis", {})
        f.write("=" * 80 + "\n")
        f.write("Deep Analysis\n")
        f.write("=" * 80 + "\n")
        for k in [
            "total_signatures", "unique_r", "repeated_r_count",
            "s_median_hex", "low_s_fraction", "high_s_fraction",
            "gcd_s", "s_bits_min", "s_bits_med", "s_bits_max"
        ]:
            if k in da:
                f.write(f"{k}: {da[k]}\n")

    print(f"[saved] {address} → {txt_path}")
    return True

def save_rnonce(vulns: List[Dict[str, Any]], address: str):
    """
    सभी reused-nonce vulnerabilities को rnonce.txt में save करता है।
    - हर r value का header एक बार लिखा जाएगा।
    - उसके नीचे उसकी सारी txid/pubkey occurrences लिखी जाएँगी।
    - हर बार पूरा file overwrite करके लिखा जाएगा (so हमेशा up-to-date रहेगा)।
    """
    if not vulns:
        return

    # memory में data update करो
    for v in vulns:
        if v["type"] != "Reused Nonce":
            continue

        try:
            r_hex = v["r"][2:] if isinstance(v.get("r"), str) and v["r"].startswith("0x") else str(v.get("r"))
        except Exception:
            r_hex = str(v.get("r"))

        for occ in v["occurrences"]:
            txid = occ.get("txid") or "N/A"
            pk = occ.get("pubkey") or "N/A"
            key = f"{txid}|{pk}"
            if key not in SAVED_R_GROUPS[r_hex]:
                SAVED_R_GROUPS[r_hex].append(key)

    # अब पूरे file को overwrite करके लिख दो
    os.makedirs("reports", exist_ok=True)
    path = os.path.join("reports", "rnonce.txt")

    with open(path, "w", encoding="utf-8") as f:
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

    print(f"[updated] rnonce groups saved → {path}")

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
        "per_address_counts": {}
    }

    # --- fetch all txs
    txs = fetch_all_transactions(address)
    report["transaction_count"] = len(txs)

    # --- extract signatures
    sigs = extract_signatures(txs)
    report["signature_count"] = len(sigs)

    # --- add signatures to GLOBAL_R_MAP for cross-address detection
    for g in sigs:
        GLOBAL_R_MAP[g["r"]].append({
            "address": address,
            "txid": g.get("txid", ""),
            "pubkey": g.get("pubkey")
        })

    # --- deep analysis
    report["deep_analysis"] = deep_analyse(sigs)

    vulns: List[Dict[str, Any]] = []

    # --- reused nonce (cross-address check)
    reused = check_reused_nonce_global(address, sigs)
    if reused:
        vulns.extend(reused)
        VULN_COUNTS["Reused Nonce"] += len(reused)
        report["per_address_counts"]["Reused Nonce"] = len(reused)
    else:
        report["per_address_counts"]["Reused Nonce"] = 0

    # --- weak RNG
    weak = check_weak_rng(sigs)
    if weak:
        vulns.append(weak)
        VULN_COUNTS["Weak RNG"] += 1
        report["per_address_counts"]["Weak RNG"] = 1
    else:
        report["per_address_counts"]["Weak RNG"] = 0

    # --- multi nonce delta
    delta = check_multi_nonce_delta(sigs)
    if delta:
        vulns.append(delta)
        VULN_COUNTS["Multi-Nonce Delta"] += 1
        report["per_address_counts"]["Multi-Nonce Delta"] = 1
    else:
        report["per_address_counts"]["Multi-Nonce Delta"] = 0

    # --- k-value signals
    ksig = check_kvalue_signals(sigs)
    if ksig:
        vulns.append(ksig)
        VULN_COUNTS["K-Value Signals"] += 1
        report["per_address_counts"]["K-Value Signals"] = 1
    else:
        report["per_address_counts"]["K-Value Signals"] = 0

    # --- final handling
    if vulns:
        VULNERABLE_ADDRESSES += 1
        report["vulnerabilities"] = vulns

    REPORTS.append(report)

    # --- save only reused-nonce vulns into one master file
    save_rnonce(vulns, address)

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

        for addr in addresses:
            if EXIT_FLAG:
                break
            analyze_address(addr)

        # --- NEW: After scanning all, save consolidated cross-address reused-r summary
        if not EXIT_FLAG:
            save_cross_address_summary()

        if not EXIT_FLAG:
            print("\nScanning completed!")
            print(f"Final: {VULNERABLE_ADDRESSES}/{TOTAL_ADDRESSES} addresses show risk signals")
            print("\nVulnerable Addresses:")
            for rep in REPORTS:
                if rep.get("vulnerabilities"):
                    print(f" - {rep['address']}")
            print("\nTXT reports saved in 'reports/' (weak K-Value reports are skipped).")
    except KeyboardInterrupt:
        sys.exit(0)

if __name__ == "__main__":
    main()
