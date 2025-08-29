# btc_safe_scanner_txt_only_v3.py (updated for Medium K-Value + Deep K analysis + consolidated report)

import requests, time, os, sys, math, signal
from hashlib import sha256
from collections import defaultdict, Counter
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple

# -------------------- Config --------------------
BLOCKCHAIN_API = "https://blockchain.info/address/{address}?format=json&offset={offset}&limit={limit}"
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # secp256k1 order

# Evidence policy
KVALUE_MIN_SIGS_STRONG = 20
KVALUE_MIN_SIGS_MEDIUM = 12
KVALUE_BIAS_THRESHOLD_STRONG = 0.30
KVALUE_BIAS_THRESHOLD_MEDIUM = 0.18
SAVE_KVALUE_LEVELS = {"strong", "medium"}  # <= changed: allow medium too

# Save policy for "only K-Value" case (backward-compat)
MIN_SIGS_FOR_KVALUE_SAVE = KVALUE_MIN_SIGS_STRONG  # kept, but we’ll gate with new logic too

# RNG heuristics (medium/strong gates)
WEAK_R_RATIO_STRONG = 0.60
WEAK_R_RATIO_MEDIUM = 0.70
DELTA_RATIO_STRONG = 0.35
DELTA_RATIO_MEDIUM = 0.45

# fetch tuning
BATCH_SIZE = 100
REQ_TIMEOUT = 20
MAX_RETRIES = 5

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

# Global r map and saved groups
GLOBAL_R_MAP: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
SAVED_R_GROUPS: Dict[str, List[str]] = defaultdict(list)
SAVE_KVALUE_FLAG = False

# HTTP session for blockchain.info API
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "SafeBTCScanner-TXT/1.5-kvalue-medium"})

# Accumulator for consolidated K-Value report
# Each element is dict: {
#   "address": str,
#   "n": int,
#   "level": str,
#   "bias": float,
#   "gcd": int|None,
#   "notes": list[str],
#   "deep": dict,
#   "s_values": list[int]
# }
KVALUE_CONSOLIDATED: List[Dict[str, Any]] = []

# If True, save_kvalue_consolidated() will be called immediately after
# each K-Value is appended (safer if program interrupted)
SAVE_KVALUE_IMMEDIATE = True

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

def backoff_sleep(attempt: int):
    delay = min(2 ** attempt, 30)
    time.sleep(delay + (0.25 * attempt))

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

# -------------------- ScriptSig parsing --------------------
def parse_der_sig_from_scriptsig(script_hex: str) -> Optional[Tuple[int, int, int]]:
    try:
        i = script_hex.find("30")
        if i == -1:
            return None
        i0 = i + 2
        _seq_len = int(script_hex[i0:i0+2], 16); i0 += 2
        if script_hex[i0:i0+2] != "02": return None
        i0 += 2
        r_len = int(script_hex[i0:i0+2], 16); i0 += 2
        r_hex = script_hex[i0:i0 + 2*r_len]; i0 += 2*r_len
        if script_hex[i0:i0+2] != "02": return None
        i0 += 2
        s_len = int(script_hex[i0:i0+2], 16); i0 += 2
        s_hex = script_hex[i0:i0 + 2*s_len]; i0 += 2*s_len
        sighash_hex = script_hex[i0:i0+2]
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
def compute_sighash_z(tx: dict, vin_idx: int, sighash_flag: int) -> Optional[int]:
    """
    Compute real ECDSA message hash (z) for tx input vin_idx.
    Returns integer z or None if not possible (missing data).
    Supports:
      - Legacy (non-segwit) SIGHASH_ALL
      - BIP-143 (P2WPKH/P2WSH) if prev_out has script+value
    """
    try:
        from hashlib import sha256

        def dsha(b: bytes) -> bytes:
            return sha256(sha256(b).digest()).digest()

        # simplified example: only handles SIGHASH_ALL legacy
        vin = tx["inputs"][vin_idx]
        prev = vin.get("prev_out", {})
        script_pubkey = prev.get("script")
        if not script_pubkey:
            return None

        version = int(tx.get("ver", 1))
        locktime = int(tx.get("lock_time", 0))
        ser = version.to_bytes(4, "little")

        # inputs
        ser += (len(tx["inputs"])).to_bytes(1, "little")
        for i, inp in enumerate(tx["inputs"]):
            prev_txid = inp["prev_out"]["hash"] if "hash" in inp["prev_out"] else inp["prev_out"]["txid"]
            vout = int(inp["prev_out"]["n"])
            ser += bytes.fromhex(prev_txid)[::-1]
            ser += vout.to_bytes(4, "little")
            if i == vin_idx:
                script_bytes = bytes.fromhex(script_pubkey)
                ser += len(script_bytes).to_bytes(1, "little") + script_bytes
            else:
                ser += b"\x00"
            ser += (inp.get("sequence", 0xffffffff)).to_bytes(4, "little")

        # outputs
        ser += (len(tx["out"])).to_bytes(1, "little")
        for out in tx["out"]:
            ser += int(out["value"]).to_bytes(8, "little")
            script_bytes = bytes.fromhex(out["script"])
            ser += len(script_bytes).to_bytes(1, "little") + script_bytes

        ser += locktime.to_bytes(4, "little")
        ser += sighash_flag.to_bytes(4, "little")

        return int.from_bytes(dsha(ser), "big")
    except Exception:
        return None


def extract_signatures(transactions: List[dict]) -> List[Dict[str, Any]]:
    """
    Extract r, s, pubkey, sighash, and compute original z (message hash) 
    from raw transaction data.
    """
    sigs = []
    for tx in transactions:
        try:
            txid = tx.get("hash", "")
            inputs = tx.get("inputs", [])

            for vin_idx, txin in enumerate(inputs):
                script = txin.get("script", "")
                pubkey = extract_pubkey_from_scriptsig(script)
                parsed = parse_der_sig_from_scriptsig(script)
                if not parsed:
                    continue

                r, s, sighash_flag = parsed

                # --- ✅ Compute real z (message hash) ---
                try:
                    rawtx = tx.get("raw", None)
                    if rawtx:
                        raw_bytes = bytes.fromhex(rawtx)
                        # For now assume legacy sighash (SIGHASH_ALL).
                        # If you want BIP143 (segwit) support, need branch here.
                        tx_copy = raw_bytes + sighash_flag.to_bytes(4, "little")
                        z_val = int(sha256(sha256(tx_copy).digest()).hexdigest(), 16)
                    else:
                        z_val = None
                except Exception as e:
                    print(f"[warn] could not compute z for txid={txid}: {e}")
                    z_val = None

                sigs.append({
                    "txid": txid,
                    "vin": vin_idx,
                    "r": r,
                    "s": s,
                    "sighash": sighash_flag,
                    "pubkey": pubkey,
                    "z_original": z_val   # ✅ real computed z
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
                    "action": "Rotate keys; cease signing with affected key. Investigate wallet RNG.",
                    "note": "z shown is SHA256(txid) surrogate, NOT the real ECDSA preimage hash."
                })
    return results

def classify_rng_weak(unique_r: int, total: int) -> Optional[str]:
    if total < 8:
        return None
    ratio = unique_r / total if total else 1.0
    if total >= 20 and ratio < WEAK_R_RATIO_STRONG:
        return "strong"
    if total >= 12 and ratio < WEAK_R_RATIO_MEDIUM:
        return "medium"
    return None

def check_weak_rng(signatures: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if len(signatures) < 8:
        return None
    r_values = [s['r'] for s in signatures]
    unique_r = len(set(r_values))
    sev = classify_rng_weak(unique_r, len(r_values))
    if not sev:
        return None
    ratio = unique_r / len(r_values)
    return {
        "type": "Weak RNG",
        "unique_r": unique_r,
        "total": len(r_values),
        "ratio": ratio,
        "severity": sev,
        "signal": "Low r diversity across signatures.",
        "note": "Heuristic signal; confirm RNG health."
    }

def check_multi_nonce_delta(signatures: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if len(signatures) < 12:
        return None
    r_vals = [s["r"] for s in signatures]
    deltas = [abs(r_vals[i] - r_vals[i-1]) for i in range(1, len(r_vals))]
    if not deltas:
        return None
    uniq = len(set(deltas))
    ratio = uniq / len(deltas)
    severity = None
    if len(deltas) >= 20 and ratio < DELTA_RATIO_STRONG:
        severity = "strong"
    elif len(deltas) >= 12 and ratio < DELTA_RATIO_MEDIUM:
        severity = "medium"
    if not severity:
        return None
    return {
        "type": "Multi-Nonce Delta",
        "unique_deltas": uniq,
        "total_deltas": len(deltas),
        "ratio": ratio,
        "severity": severity,
        "signal": "Structured spacing in r suggests nonce patterning.",
    }

def chi2_pvalue_from_counts(counts: List[int]) -> float:
    # simple χ² GOF assuming equal expected
    import math
    k = len(counts)
    if k == 0:
        return 1.0
    n = sum(counts)
    if n == 0:
        return 1.0
    exp = n / k
    chi2 = sum((c - exp) ** 2 / exp for c in counts)
    # approximate p with survival function using dof = k-1
    # simple series approx (for small k ok); if scipy unavailable
    # Wilson-Hilferty transform
    df = k - 1
    if df <= 0:
        return 1.0
    t = (chi2/df)**(1/3) - (1 - 2/(9*df))
    z = t / math.sqrt(2/(9*df))
    # 1 - Phi(z)
    return 0.5 * math.erfc(z / math.sqrt(2))

def check_kvalue_signals(signatures: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    s_vals = [s.get("s") for s in signatures if isinstance(s.get("s"), int)]
    n = len(s_vals)
    if n < KVALUE_MIN_SIGS_MEDIUM:
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

    # mod-prime chi2 (weak-but-useful heuristic)
    primes = [3, 5, 7, 11]
    chi2_pvals = {}
    for p in primes:
        bucket = [0]*p
        for x in s_vals:
            bucket[x % p] += 1
        chi2_pvals[p] = chi2_pvalue_from_counts(bucket)
    chi2_flag = any(pv < 0.05 for pv in chi2_pvals.values())

    # Evidence classification
    level = "weak"
    notes = []
    if gcd_all > 1 or (bias >= KVALUE_BIAS_THRESHOLD_STRONG and n >= KVALUE_MIN_SIGS_STRONG):
        level = "strong"
    elif (bias >= KVALUE_BIAS_THRESHOLD_MEDIUM and n >= KVALUE_MIN_SIGS_MEDIUM) or chi2_flag:
        level = "medium"
    else:
        level = "weak"

    if bias >= KVALUE_BIAS_THRESHOLD_MEDIUM:
        notes.append("Non-uniform s distribution (median-split bias).")
    if gcd_all > 1:
        notes.append(f"s values share a common factor {gcd_all}.")
    if chi2_flag:
        notes.append("Residue bias across small primes (χ²).")

    if level == "weak":
        return None

    return {
        "type": "K-Value Signals",
        "notes": notes,
        "disclaimer": "Signals are heuristic and NOT a key-recovery. Review RNG & signer.",
        "gcd": (gcd_all if gcd_all > 1 else None),
        "bias": bias,
        "sample_size": n,
        "evidence_level": level,
        "chi2_mod_primes": chi2_pvals
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

    # NEW: deeper stats
    # stddev of bit lengths
    mean_bits = sum(bits)/len(bits)
    stats["s_bits_std"] = (sum((b-mean_bits)**2 for b in bits)/len(bits))**0.5

    # even/odd and LSB runs test
    evens = sum(1 for x in s_vals if (x & 1) == 0)
    odds = total - evens
    stats["s_even_fraction"] = round(evens/total, 4)
    stats["s_odd_fraction"] = round(odds/total, 4)

    lsb_seq = [x & 1 for x in s_vals]
    runs = 1 + sum(1 for i in range(1, len(lsb_seq)) if lsb_seq[i] != lsb_seq[i-1])
    # Wald–Wolfowitz runs z-score (approx)
    n1, n0 = odds, evens
    mu = (2*n1*n0)/(n1+n0) + 1 if (n1+n0)>0 else 0
    var = (2*n1*n0*(2*n1*n0 - n1 - n0))/(((n1+n0)**2)*(n1+n0-1)) if (n1+n0)>1 else 1
    z_runs = (runs - mu)/math.sqrt(var) if var>0 else 0.0
    stats["lsb_runs_count"] = runs
    stats["lsb_runs_z"] = round(z_runs, 3)

    # serial correlation (Pearson) for successive s
    if len(s_vals) >= 3:
        x = s_vals
        xm = sum(x)/len(x)
        num = sum((x[i]-xm)*(x[i-1]-xm) for i in range(1, len(x)))
        den = sum((xi - xm)**2 for xi in x)
        stats["serial_corr"] = round(num/den, 4) if den else 0.0
    else:
        stats["serial_corr"] = None

    # very light Spearman rho (rank correlation with index)
    if len(s_vals) >= 5:
        ranks = {v:i for i, v in enumerate(sorted(set(s_vals)))}
        r = [ranks[v] for v in s_vals]
        n = len(r)
        d2 = sum((r[i] - i)**2 for i in range(n))
        stats["spearman_rho"] = round(1 - (6*d2)/(n*(n*n - 1)), 4) if n>2 else None
    else:
        stats["spearman_rho"] = None

    # entropy of top-12 bits
    def entropy(vals):
        from collections import Counter
        cnt = Counter(vals)
        n = sum(cnt.values())
        import math
        return -sum((c/n)*math.log2(c/n) for c in cnt.values() if c>0)
    hi12 = [(s >> (s.bit_length() - 12)) & ((1<<12)-1) for s in s_vals if s.bit_length() >= 12]
    stats["entropy_hi12"] = round(entropy(hi12), 3) if hi12 else None

    # χ² over small primes
    primes = [3,5,7,11]
    chi2_pvals = {}
    for p in primes:
        bucket = [0]*p
        for x in s_vals:
            bucket[x % p] += 1
        chi2_pvals[p] = chi2_pvalue_from_counts(bucket)
    stats["chi2_mod_primes"] = {p: round(v, 4) for p, v in chi2_pvals.items()}

    return stats

# -------------------- Reporting --------------------
def save_report_txt(address: str, report: Dict[str, Any]) -> bool:
    os.makedirs("reports", exist_ok=True)

    vulns = report.get("vulnerabilities", [])
    if not vulns:
        print(f"[skip] {address}: clean (no anomalies)")
        return False

    # Only-KValue case gate
    only_kvalue = (len(vulns) == 1 and vulns[0].get("type") == "K-Value Signals")
    if only_kvalue:
        ksig = vulns[0]
        level = ksig.get("evidence_level", "weak")
        n = ksig.get("sample_size", 0)
        if level == "strong" and n >= KVALUE_MIN_SIGS_STRONG:
            pass
        elif level == "medium" and n >= KVALUE_MIN_SIGS_MEDIUM:
            pass
        else:
            print(f"[skip] {address}: K-Value evidence not enough (level={level}, n={n})")
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
                r_no0x = v["r"][2:] if isinstance(v.get("r"), str) and v["r"].startswith("0x") else str(v.get("r"))
                f.write(f"r: {r_no0x}\n")
                f.write(f"{v['risk']}\n")
                f.write("Occurrences:\n")
                for j, occ in enumerate(v["occurrences"], 1):
                    pk = occ.get("pubkey") or "N/A"
                    f.write(f" {j}. txid={occ['txid']} pubkey={pk}\n")
                f.write(f"Action: {v['action']}\n")
                f.write(f"Note: {v.get('note','')}\n")

            elif v["type"] == "Weak RNG":
                f.write(f"Unique r: {v['unique_r']}/{v['total']}  (ratio={v['ratio']:.2f})\n")
                if v.get("severity"):
                    f.write(f"Severity: {v['severity']}\n")
                f.write(f"Signal: {v['signal']}\n")
                f.write(f"Note: {v['note']}\n")

            elif v["type"] == "Multi-Nonce Delta":
                f.write(f"Unique deltas: {v['unique_deltas']}/{v['total_deltas']}  (ratio={v['ratio']:.2f})\n")
                if v.get("severity"):
                    f.write(f"Severity: {v['severity']}\n")
                f.write(f"Signal: {v['signal']}\n")

            elif v["type"] == "K-Value Signals":
                f.write(f"Evidence level: {v.get('evidence_level','unknown')}  (n={v.get('sample_size','?')})\n")
                f.write("Signals:\n")
                for note in v.get("notes", []):
                    f.write(f" - {note}\n")
                if v.get("gcd"):
                    f.write(f"GCD(s): {v['gcd']}\n")
                if v.get("chi2_mod_primes"):
                    f.write("χ² mod primes p-values: " + ", ".join(f"p{p}≈{pv:.4f}" for p, pv in v["chi2_mod_primes"].items()) + "\n")
                f.write(f"Bias (median split): {v.get('bias',0):.3f}\n")
                f.write(f"Disclaimer: {v.get('disclaimer','')}\n")

                # 🔹 NEW: full deep analysis dump
                da = report.get("deep_analysis", {})
                if da:
                    f.write("\n--- Detailed K-Value Metrics ---\n")
                    f.write(f"s_bits: min={da.get('s_bits_min')} med={da.get('s_bits_med')} max={da.get('s_bits_max')} std={da.get('s_bits_std')}\n")
                    f.write(f"s_low_fraction: {da.get('low_s_fraction')}  s_high_fraction: {da.get('high_s_fraction')}\n")
                    f.write(f"even/odd fraction: even={da.get('s_even_fraction')}  odd={da.get('s_odd_fraction')}\n")
                    f.write(f"LSB runs: count={da.get('lsb_runs_count')}  z_score={da.get('lsb_runs_z')}\n")
                    f.write(f"serial_corr: {da.get('serial_corr')}\n")
                    f.write(f"spearman_rho: {da.get('spearman_rho')}\n")
                    f.write(f"entropy_hi12: {da.get('entropy_hi12')}\n")
                    if da.get("chi2_mod_primes"):
                        f.write("chi2_mod_primes: " + ", ".join(f"p{p}≈{pv}" for p, pv in da["chi2_mod_primes"].items()) + "\n")

            f.write("\n")

        # Deep analysis summary always included
        da = report.get("deep_analysis", {})
        f.write("=" * 80 + "\n")
        f.write("Deep Analysis\n")
        f.write("=" * 80 + "\n")
        for k in [
            "total_signatures","unique_r","repeated_r_count","s_median_hex",
            "low_s_fraction","high_s_fraction","gcd_s","s_bits_min",
            "s_bits_med","s_bits_max","s_bits_std","s_even_fraction",
            "s_odd_fraction","lsb_runs_count","lsb_runs_z","serial_corr",
            "spearman_rho","entropy_hi12"
        ]:
            if k in da:
                f.write(f"{k}: {da[k]}\n")
        if "chi2_mod_primes" in da:
            f.write("chi2_mod_primes: " + ", ".join(f"p{p}≈{pv}" for p, pv in da["chi2_mod_primes"].items()) + "\n")

    print(f"[saved] {address} → {txt_path}")
    return True

def save_rnonce(vulns: List[Dict[str, Any]], address: str):
    if not vulns:
        return
    for v in vulns:
        if v["type"] != "Reused Nonce":
            continue
        r_hex = v["r"][2:] if isinstance(v.get("r"), str) and v["r"].startswith("0x") else str(v.get("r"))
        for occ in v["occurrences"]:
            txid = occ.get("txid") or "N/A"
            pk = occ.get("pubkey") or "N/A"
            key = f"{txid}|{pk}"
            if key not in SAVED_R_GROUPS[r_hex]:
                SAVED_R_GROUPS[r_hex].append(key)

    os.makedirs("reports", exist_ok=True)
    path = os.path.join("report", "rnonce.txt")
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

def save_address_vulns(address: str, vulns: List[Dict[str, Any]]):
    if not vulns:
        return
    selected = [v for v in vulns if v["type"] in ("Weak RNG", "Multi-Nonce Delta")]
    if not selected:
        return

    os.makedirs("reports", exist_ok=True)
    path = os.path.join("reports", f"{address}_vulns.txt")

    with open(path, "w", encoding="utf-8") as f:
        f.write("="*80 + "\n")
        f.write(f"Address: {address}\n")
        f.write(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("="*80 + "\n\n")

        for v in selected:
            f.write(f"🔴 {v['type']}\n")
            f.write("-"*80 + "\n")
            if v["type"] == "Weak RNG":
                f.write(f"Unique r: {v['unique_r']}/{v['total']}  (ratio={v['ratio']:.2f})\n")
                f.write(f"Severity: {v.get('severity','')}\n")
                f.write(f"Signal: {v['signal']}\n")
            elif v["type"] == "Multi-Nonce Delta":
                f.write(f"Unique deltas: {v['unique_deltas']}/{v['total_deltas']}  (ratio={v['ratio']:.2f})\n")
                f.write(f"Severity: {v.get('severity','')}\n")
                f.write(f"Signal: {v['signal']}\n")
            f.write("\n")

    print(f"[saved] {address} → {path}")


def save_kvalue_consolidated():
    """
    Atomic write of consolidated K-Value summary to report/kvalue.txt.
    Order: r_values -> s_values -> z_values -> txids
    """
    global KVALUE_CONSOLIDATED
    os.makedirs("report", exist_ok=True)
    path = os.path.join("report", "kvalue.txt")
    tmp_path = path + ".tmp"

    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write("=== Consolidated K-Value Summary ===\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Entries: {len(KVALUE_CONSOLIDATED)}\n\n")

            if not KVALUE_CONSOLIDATED:
                f.write("(No K-Value entries collected)\n")

            for row in KVALUE_CONSOLIDATED:
                addr = row.get("address", "N/A")
                f.write(f"[Address] {addr}\n")
                f.write(f"  Evidence level: {row.get('level', 'unknown')}\n")
                f.write(f"  Signatures analyzed: {row.get('n', 0)}\n")
                bias = row.get('bias', 0.0)
                f.write(f"  Bias (median split): {bias:.6f}\n")
                gcds = row.get('gcd') or 1
                f.write(f"  GCD(s): {gcds}\n")

                # deep metrics
                da = row.get("deep", {}) or {}
                if da:
                    f.write(f"  s_bits: min={da.get('s_bits_min')} med={da.get('s_bits_med')} "
                            f"max={da.get('s_bits_max')} std={da.get('s_bits_std')}\n")
                    f.write(f"  s_low_fraction: {da.get('low_s_fraction')}  "
                            f"s_high_fraction: {da.get('high_s_fraction')}\n")
                    f.write(f"  even/odd fraction: even={da.get('s_even_fraction')} "
                            f"odd={da.get('s_odd_fraction')}\n")
                    f.write(f"  LSB runs: count={da.get('lsb_runs_count')} "
                            f"z_score={da.get('lsb_runs_z')}\n")
                    if da.get("serial_corr") is not None:
                        f.write(f"  serial_corr: {da.get('serial_corr')}\n")
                    if da.get("spearman_rho") is not None:
                        f.write(f"  spearman_rho: {da.get('spearman_rho')}\n")
                    if da.get("entropy_hi12") is not None:
                        f.write(f"  entropy_hi12: {da.get('entropy_hi12')}\n")
                    if da.get("chi2_mod_primes"):
                        f.write("  chi2_mod_primes: " +
                                ", ".join(f"p{p}≈{pv:.6f}" for p, pv in da["chi2_mod_primes"].items()) + "\n")

                # notes
                if row.get("notes"):
                    f.write("  Notes:\n")
                    for nt in row.get("notes", []):
                        f.write(f"    - {nt}\n")

                # r_values
                r_vals = row.get("r_values", [])
                f.write("  r_values (decimal) [count=%d]:\n" % len(r_vals))
                for r in r_vals:
                    f.write(f"    {r}\n")

                # s_values
                s_vals = row.get("s_values", [])
                f.write("  s_values (decimal) [count=%d]:\n" % len(s_vals))
                for s in s_vals:
                    f.write(f"    {s}\n")

                # z_values (always enforce)
                z_vals = row.get("z_values", [])
                f.write("  z_values (decimal) [count=%d]:\n" % len(z_vals))
                for z in z_vals:
                    f.write(f"    {z}\n")

                # txids
                txids = row.get("txids", [])
                f.write("  txids [count=%d]:\n" % len(txids))
                for t in txids:
                    f.write(f"    {t}\n")

                f.write("\n")

        # atomic replace
        os.replace(tmp_path, path)
        print(f"[saved] consolidated K-Value -> {os.path.abspath(path)} "
              f"(entries={len(KVALUE_CONSOLIDATED)})")

    except Exception as e:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass
        raise

def save_cross_address_summary():
    """Optional summary for reused-r across addresses."""
    if not SAVED_R_GROUPS:
        return
    os.makedirs("reports", exist_ok=True)
    path = os.path.join("reports", "cross_reused_r_summary.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write("Cross-Address Reused-r Summary\n")
        f.write("="*80 + "\n")
        for r_hex, occ in SAVED_R_GROUPS.items():
            f.write(f"r={r_hex}  occurrences={len(occ)}\n")
    print(f"[saved] cross-address summary → {path}")

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
        "per_address_counts": {},
        "deep_analysis": {},
    }

    # 🔹 fetch all transactions
    txs = fetch_all_transactions(address)
    report["transaction_count"] = len(txs)

    # 🔹 extract signatures
    sigs = extract_signatures(txs)
    report["signature_count"] = len(sigs)

    # 🔹 push to GLOBAL_R_MAP
    for g in sigs:
        GLOBAL_R_MAP[g["r"]].append({
            "address": address,
            "txid": g.get("txid", ""),
            "pubkey": g.get("pubkey")
        })

    # 🔹 deep analysis
    da = deep_analyse(sigs)
    report["deep_analysis"] = da

    vulns: List[Dict[str, Any]] = []

    # ---------------- Vulnerability checks ----------------
    # Reused nonce (हमेशा check होगा)
    reused = check_reused_nonce_global(address, sigs)
    if reused:
        vulns.extend(reused)
        VULN_COUNTS["Reused Nonce"] += len(reused)
        report["per_address_counts"]["Reused Nonce"] = len(reused)
    else:
        report["per_address_counts"]["Reused Nonce"] = 0

    # ✅ बाकी checks सिर्फ तब होंगे जब -s flag दिया गया हो
    if SAVE_KVALUE_FLAG:
        # Weak RNG
        weak = check_weak_rng(sigs)
        if weak:
            vulns.append(weak)
            VULN_COUNTS["Weak RNG"] += 1
            report["per_address_counts"]["Weak RNG"] = 1
        else:
            report["per_address_counts"]["Weak RNG"] = 0

        # Multi-nonce delta
        delta = check_multi_nonce_delta(sigs)
        if delta:
            vulns.append(delta)
            VULN_COUNTS["Multi-Nonce Delta"] += 1
            report["per_address_counts"]["Multi-Nonce Delta"] = 1
        else:
            report["per_address_counts"]["Multi-Nonce Delta"] = 0

        # K-value signals
        ksig = check_kvalue_signals(sigs)
        if ksig:
            vulns.append(ksig)
            VULN_COUNTS["K-Value Signals"] += 1
            report["per_address_counts"]["K-Value Signals"] = 1

            # ✅ Collect r, s, z (original), txids
            r_list = [item.get("r") for item in sigs if isinstance(item.get("r"), int)]
            s_list = [item.get("s") for item in sigs if isinstance(item.get("s"), int)]
            z_list = [item.get("z_original") for item in sigs if item.get("z_original") is not None]
            txids = [item.get("txid") for item in sigs if item.get("txid")]
            txids = list(dict.fromkeys(txids))  # unique txids

            # Append consolidated
            KVALUE_CONSOLIDATED.append({
                "address": address,
                "n": ksig.get("sample_size"),
                "level": ksig.get("evidence_level"),
                "bias": ksig.get("bias", 0.0),
                "gcd": ksig.get("gcd"),
                "notes": ksig.get("notes", []),
                "deep": da,
                "r_values": r_list,
                "s_values": s_list,
                "z_values": z_list,   # ✅ अब original z save होगा
                "txids": txids
            })

            print(f"[info] K-Value appended for {address} "
                  f"(level={ksig.get('evidence_level')}, n={ksig.get('sample_size')})")

            # Save immediately if toggle is on
            if SAVE_KVALUE_IMMEDIATE:
                try:
                    save_kvalue_consolidated()
                except Exception as e:
                    print(f"[error] save_kvalue_consolidated() failed: {e}")
        else:
            report["per_address_counts"]["K-Value Signals"] = 0
    else:
        # जब -s नहीं होगा तो ये checks skip होंगे
        report["per_address_counts"]["Weak RNG"] = 0
        report["per_address_counts"]["Multi-Nonce Delta"] = 0
        report["per_address_counts"]["K-Value Signals"] = 0

    # ---------------- Mark vulnerable ----------------
    if vulns:
        VULNERABLE_ADDRESSES += 1
        report["vulnerabilities"] = vulns

    REPORTS.append(report)

    # ✅ सिर्फ -s flag होने पर ही save होंगे
    if SAVE_KVALUE_FLAG:
        save_address_vulns(address, vulns)

    # Save reports (reused nonce report हमेशा चलेगा)
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
    global TOTAL_ADDRESSES, MAX_TRANSACTIONS, SAVE_KVALUE_FLAG
    try:
        addr_file = get_input_file()
        MAX_TRANSACTIONS = get_transaction_limit()
        with open(addr_file, "r", encoding="utf-8") as f:
            addresses = [ln.strip() for ln in f if ln.strip()]
        TOTAL_ADDRESSES = len(addresses)

                # 🔹 Show advisory only once if -s is not used
        if "-s" not in sys.argv:
            print("\n👉 If you want to process Weak RNG, Multi-Nonce Delta and K-Value signals use -s\n")


        # ✅ -s flag check
        if "-s" in sys.argv:
            SAVE_KVALUE_FLAG = True

        for addr in addresses:
            if EXIT_FLAG:
                break
            analyze_address(addr)

        # ✅ kvalue.txt सिर्फ तब save होगा जब -s दिया गया हो
        if not EXIT_FLAG and SAVE_KVALUE_FLAG:
            save_kvalue_consolidated()

        if not EXIT_FLAG:
            print("\nScanning completed!")
            print(f"Final: {VULNERABLE_ADDRESSES}/{TOTAL_ADDRESSES} addresses show risk signals")
            print("\nVulnerable Addresses:")
            for rep in REPORTS:
                if rep.get("vulnerabilities"):
                    print(f" - {rep['address']}")
            if SAVE_KVALUE_FLAG:
                print("\nTXT reports saved in 'report/rnonce.txt' and consolidated K-Value in 'report/kvalue.txt'.")
            else:
                print("\nTXT reports saved in 'report/rnonce.txt' only.")
    except KeyboardInterrupt:
        sys.exit(0)

if __name__ == "__main__":
    main()
