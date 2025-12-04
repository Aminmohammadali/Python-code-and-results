#!/usr/bin/env python3
# verifier_pi_batch.py
# -----------------------------------------------------
# Raspberry Pi VERIFIER optimized for batch verification
# WITH OPTIONAL SYBIL ATTACK DETECTION + TIMESTAMP CHECK
#
# - Messages are "ts||msg".
# - We compare ts with EXPECTED_TS_STR.
#   * If ts != EXPECTED_TS_STR -> replay / invalid: signature is ignored.
#   * If ts == EXPECTED_TS_STR -> signature is eligible for verification.
#
# Sybil detection (default ON):
# - Global T2-based tracking (signer identity).
# - Per-batch T1-based duplicate detection:
#   * Only FIRST signature per T1 participates in batch equation.
#   * Duplicates ignored.
#   * If any duplicates are ignored, batch FAILS.
#
# Sybil OFF (--disable-sybil):
# - No T2 tracking.
# - No T1 duplicate check.
# - All eligible signatures (correct ts) participate.

import argparse, json, socket, struct, hashlib, sys, time, threading
from collections import defaultdict
from bplib import bp
from bplib.bp import BpGroup
from petlib.bn import Bn

# ============================
# Global toggles / parameters
# ============================

SYBIL_ENABLED = True  # can be disabled with --disable-sybil

# Expected timestamp used for replay detection (ts in "ts||msg")
EXPECTED_TS_STR = "1212122323"
EXPECTED_TS = int(EXPECTED_TS_STR)

# ============================
# Predefined public parameters (MUST match the signer)
# ============================
H_HEX = "021671ad1d26a4f36a13d7e784c30f5fb8a2dbdd520f96c68c28158317120c0194"
H1_HEX = "020d88e6287ceaf04a0686abd6bad9325dfee53a9c2606b37b62122cf611c1a4fe"
Y_HEX = "021483d905ed81ae2a6c267bc339777fe15380e1403f924268d888e85c29b0a7e6"
W_HEX = "15749bbf9d02337fb8cc860a256350ef4ae07eb8c148825db06911612d5c6a940bab2361cd512c36098308259502631adb4bd594c06fae47249a68b2a922459d075308a6d76f5004c268e5434059224398be1ac87c0e29b513b6ce82b50637ab158329a65a7da006e60debf1f4cfc0857de22f32568296a4c8cc310be7297677"

# ============================
# Helpers
# ============================

def clean_hex(s: str) -> str:
    if s is None:
        return ""
    return s.replace("<", "").replace(">", "").replace("0x", "").replace(" ", "").strip()

def _g1_from_hex(h: str, G: BpGroup):
    return bp.G1Elem.from_bytes(bytes.fromhex(clean_hex(h)), G)

def _g2_from_hex(h: str, G: BpGroup):
    return bp.G2Elem.from_bytes(bytes.fromhex(clean_hex(h)), G)

def _bn_from_hex(h: str):
    return Bn.from_binary(bytes.fromhex(clean_hex(h)))

def _hash_to_Zp(data: bytes, p: Bn) -> Bn:
    digest = hashlib.sha256(data).digest()
    n = int.from_bytes(digest, "big")
    n_bytes = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
    return Bn.from_binary(n_bytes) % p

def _hash_to_g1(data: bytes, g1, p):
    return _hash_to_Zp(data, p) * g1

def recv_json(conn: socket.socket) -> dict:
    hdr = conn.recv(4)
    if len(hdr) < 4:
        raise ConnectionError("Short read on header")
    (length,) = struct.unpack("!I", hdr)
    buf = b""
    while len(buf) < length:
        chunk = conn.recv(length - len(buf))
        if not chunk:
            raise ConnectionError("Short read on payload")
        buf += chunk
    return json.loads(buf.decode("utf-8"))

def send_json(conn: socket.socket, obj: dict):
    data = json.dumps(obj).encode("utf-8")
    conn.sendall(struct.pack("!I", len(data)))
    conn.sendall(data)

def _message_to_bytes(msg: str) -> bytes:
    """
    msg is "ts||payload" (string).
    We re-encode ts as big-endian bytes and append payload bytes.
    """
    ts_str, D_str = msg.split("||", 1)
    ts = int(ts_str)
    D_bytes = D_str.encode("utf-8")
    ts_bytes = ts.to_bytes((ts.bit_length() + 7) // 8 or 1, "big")
    return ts_bytes + D_bytes

# ============================
# Build params
# ============================

G = BpGroup()
p = G.order()
g1 = G.gen1()
g2 = G.gen2()

h = _g1_from_hex(H_HEX, G)
h1 = _g1_from_hex(H1_HEX, G)
Y = _g1_from_hex(Y_HEX, G)
w = _g2_from_hex(W_HEX, G)

gpk = {"g1": g1, "g2": g2, "h": h, "h1": h1, "Y": Y, "w": w}

# ============================
# Sybil Attack Detection (global, keyed by T2)
# ============================

class SybilDetector:
    """
    Tracks T2 values to detect multiple signatures from same signer identity.

    - T2 is treated as the "signer identity".
    - When the same T2 appears more than once over time, it is marked as Sybil-like.
    """
    def __init__(self):
        self.lock = threading.Lock()
        self.t2_registry = defaultdict(list)
        self.t2_counts = defaultdict(int)
        self.t2_first_seen = {}

    def register_signature(self, T2_hex: str, sig_info: dict):
        with self.lock:
            if T2_hex not in self.t2_first_seen:
                self.t2_first_seen[T2_hex] = time.time()
            self.t2_counts[T2_hex] += 1
            self.t2_registry[T2_hex].append({
                "timestamp": time.time(),
                "message": sig_info.get("message", ""),
                "source": sig_info.get("source", "unknown"),
                "T1_hex": sig_info.get("T1_hex", "")[:16] + "..."
            })
            return self.t2_counts[T2_hex]

    def check_sybil(self, T2_hex: str) -> dict:
        with self.lock:
            count = self.t2_counts.get(T2_hex, 0)
            history = self.t2_registry.get(T2_hex, [])
            first_seen = self.t2_first_seen.get(T2_hex, time.time())
            return {
                "is_sybil": count > 1,
                "total_count": count,
                "first_seen": first_seen,
                "time_span_seconds": time.time() - first_seen if count > 1 else 0,
                "previous_signatures": history[:-1] if count > 1 else []
            }

    def get_statistics(self):
        with self.lock:
            total_unique_signers = len(self.t2_registry)
            sybil_signers = sum(1 for c in self.t2_counts.values() if c > 1)
            total_sybil_sigs = sum(c - 1 for c in self.t2_counts.values() if c > 1)
            total_signatures = sum(self.t2_counts.values())
            top_offenders = sorted(
                [(t2, c) for t2, c in self.t2_counts.items() if c > 1],
                key=lambda x: x[1],
                reverse=True
            )[:10]
            return {
                "total_signatures": total_signatures,
                "unique_signers": total_unique_signers,
                "sybil_signers": sybil_signers,
                "total_sybil_signatures": total_sybil_sigs,
                "sybil_rate": (total_sybil_sigs / total_signatures * 100) if total_signatures > 0 else 0,
                "top_offenders": [
                    {
                        "T2_hex": t2[:16] + "...",
                        "signature_count": c,
                        "first_seen": self.t2_first_seen.get(t2, 0),
                        "timespan_sec": time.time() - self.t2_first_seen.get(t2, time.time())
                    }
                    for t2, c in top_offenders
                ]
            }

    def clear(self):
        with self.lock:
            self.t2_registry.clear()
            self.t2_counts.clear()
            self.t2_first_seen.clear()

sybil_detector = SybilDetector()

# ============================
# Statistics tracking
# ============================

class VerifierStats:
    def __init__(self):
        self.lock = threading.Lock()
        self.total_batches = 0
        self.total_signatures = 0  # effective signatures considered
        self.successful_batches = 0
        self.failed_batches = 0
        self.sybil_detected_batches = 0
        self.verification_times = []
        self.ping_count = 0

    def record_batch(self, sig_count, verify_time, success, sybil_detected=False):
        with self.lock:
            self.total_batches += 1
            self.total_signatures += sig_count
            if success:
                self.successful_batches += 1
            else:
                self.failed_batches += 1
            if sybil_detected and SYBIL_ENABLED:
                self.sybil_detected_batches += 1
            if len(self.verification_times) < 10000:
                self.verification_times.append(verify_time)

    def record_ping(self):
        with self.lock:
            self.ping_count += 1

    def get_summary(self):
        with self.lock:
            if self.verification_times:
                avg_time = sum(self.verification_times) / len(self.verification_times)
                min_time = min(self.verification_times)
                max_time = max(self.verification_times)
            else:
                avg_time = min_time = max_time = 0
            return {
                "total_batches": self.total_batches,
                "total_signatures": self.total_signatures,
                "successful_batches": self.successful_batches,
                "failed_batches": self.failed_batches,
                "sybil_detected_batches": self.sybil_detected_batches,
                "ping_requests": self.ping_count,
                "avg_verification_ms": avg_time * 1000,
                "min_verification_ms": min_time * 1000,
                "max_verification_ms": max_time * 1000,
            }

stats = VerifierStats()

# ============================
# Verify (single signature)
# ============================

def ARA_Verify(gpk, sigma_hex: dict, source_addr=None) -> dict:
    T1_hex = sigma_hex["T1_hex"]
    T2_hex = sigma_hex["T2_hex"]
    T1 = _g1_from_hex(T1_hex, G)
    T2 = _g1_from_hex(T2_hex, G)
    T3 = _g1_from_hex(sigma_hex["T3_hex"], G)
    T4 = _g1_from_hex(sigma_hex["T4_hex"], G)
    c = _bn_from_hex(sigma_hex["c_hex"])
    s_k = _bn_from_hex(sigma_hex["s_k_hex"])
    s_x = _bn_from_hex(sigma_hex["s_x_hex"])
    s_d = _bn_from_hex(sigma_hex["s_d_hex"])
    s_y = _bn_from_hex(sigma_hex["s_y_hex"])

    # ---- Parse message and check timestamp (ts||msg) ----
    replay_detected = False
    ts_val = None

    if "message_str" in sigma_hex and sigma_hex["message_str"]:
        msg_str = sigma_hex["message_str"]
        try:
            ts_str, _ = msg_str.split("||", 1)
            ts_val = int(ts_str)
            if ts_val != EXPECTED_TS:
                replay_detected = True
        except Exception:
            # Bad format -> treat as replay / invalid
            replay_detected = True

        M = _message_to_bytes(msg_str)
    else:
        # No message_str given: fall back to raw M_hex, no timestamp check
        M = bytes.fromhex(clean_hex(sigma_hex["M_hex"]))
        msg_str = sigma_hex.get("M_hex", "")

    # ---- Sybil tracking (global, by T2) – optional ----
    if SYBIL_ENABLED:
        sig_info = {"message": msg_str, "source": source_addr, "T1_hex": T1_hex}
        count = sybil_detector.register_signature(T2_hex, sig_info)
        sybil_info = sybil_detector.check_sybil(T2_hex)
        sybil_detected = sybil_info["is_sybil"]
        sybil_details = sybil_info if sybil_detected else None
    else:
        count = 1
        sybil_detected = False
        sybil_details = None

    g1 = gpk['g1']; g2 = gpk['g2']; h = gpk['h']; h1 = gpk['h1']; w = gpk['w']; Y = gpk['Y']
    Hm = _hash_to_g1(M, g1, p)

    if replay_detected:
        # Do NOT do heavy pairings; immediately treat as invalid
        verification_ok = False
    else:
        # Normal verification
        R1_dash = (s_k * g1) + ((-c) * T2)
        R2_dash = (s_x * T2) + ((-s_d) * g1)
        c_dash = _hash_to_Zp(
            T1.export() + T2.export() + T3.export() + T4.export() +
            R1_dash.export() + R2_dash.export() + M,
            p
        )

        KK = T4 + (-s_x) * T3 + c * T1 + s_k * Y + c * g1 + (-s_x) * Hm + (-s_y) * h1 + s_d * h
        e_KK_g2 = G.pair(KK, g2)
        e_cT3_w = G.pair(c * T3, w)

        verification_ok = (c_dash == c) and (e_KK_g2 == e_cT3_w)

    return {
        "verification_ok": bool(verification_ok),
        "sybil_detected": sybil_detected if SYBIL_ENABLED else False,
        "signature_count_from_this_signer": count,
        "sybil_details": sybil_details,
        "replay_detected": replay_detected,
        "timestamp_received": str(ts_val) if ts_val is not None else None,
        "timestamp_expected": EXPECTED_TS_STR,
    }

# ============================
# Verify (batch with split checks + timestamp + optional Sybil)
# ============================

def verify_batch_split(gpk, sig_list, source_addr=None):
    """
    Batch verification with:
    - Timestamp check ts == EXPECTED_TS_STR (per signature).
    - Optional T1-based duplicate / Sybil handling.

    Behavior:
    - Any signature with wrong ts is treated as replay and IGNORED.
    - When SYBIL_ENABLED:
        * T1 duplicates are ignored; if any duplicates ignored -> batch FAILS.
    - When SYBIL_ENABLED is False:
        * No T1-based ignoring; all eligible (ts OK) signatures participate.
    """
    t_start = time.time()

    g1 = gpk['g1']; g2 = gpk['g2']; h = gpk['h']; h1 = gpk['h1']; w = gpk['w']; Y = gpk['Y']

    n = len(sig_list)
    total_received = n

    # Part 1 includes: timestamp screening + Schnorr checks.
    t1_start = time.time()

    part1_results = [None] * n

    # First pass: timestamp check + determine common message M0 over eligible signatures.
    eligible = [False] * n
    replay_detected_batch = False
    replays_ignored = 0

    M0 = None

    for idx, sig in enumerate(sig_list):
        T1_hex = sig["T1_hex"]
        T2_hex = sig["T2_hex"]
        msg_str = sig.get("message_str", sig.get("M_hex", ""))

        short_T1 = T1_hex[:16] + "..."
        short_T2 = T2_hex[:16] + "..."

        # We require message_str with "ts||msg" for timestamp check.
        if "message_str" in sig and sig["message_str"]:
            ts_ok = True
            ts_val = None
            try:
                ts_str, _ = sig["message_str"].split("||", 1)
                ts_val = int(ts_str)
                if ts_val != EXPECTED_TS:
                    ts_ok = False
            except Exception:
                ts_ok = False

            if not ts_ok:
                replay_detected_batch = True
                replays_ignored += 1
                part1_results[idx] = {
                    "index": idx,
                    "ok": None,
                    "ignored": True,
                    "reason": "timestamp_mismatch",
                    "T1_hex": short_T1,
                    "T2_hex": short_T2,
                    "ts_received": str(ts_val) if ts_val is not None else None,
                    "expected_ts": EXPECTED_TS_STR,
                    "message": msg_str[:50] + "..." if len(msg_str) > 50 else msg_str,
                }
                continue

            # ts is OK -> build M_i
            M_i = _message_to_bytes(sig["message_str"])
        else:
            # No message_str -> treat as invalid / replayed format
            replay_detected_batch = True
            replays_ignored += 1
            part1_results[idx] = {
                "index": idx,
                "ok": None,
                "ignored": True,
                "reason": "no_message_str",
                "T1_hex": short_T1,
                "T2_hex": short_T2,
                "ts_received": None,
                "expected_ts": EXPECTED_TS_STR,
                "message": msg_str[:50] + "..." if len(msg_str) > 50 else msg_str,
            }
            continue

        # Enforce identical message M_i among eligible signatures (for aggregation correctness).
        if M0 is None:
            M0 = M_i
        else:
            if M_i != M0:
                # Different messages among eligible signatures: cannot aggregate securely.
                return {
                    "ok": False,
                    "part1_all": False,
                    "part1_results": part1_results,
                    "part2": False,
                    "sybil_detected": False,
                    "sybil_attacks": None,
                    "replay_detected": replay_detected_batch,
                    "unique_signers": 0,
                    "total_signatures_received": total_received,
                    "duplicates_ignored": 0,
                    "replays_ignored": replays_ignored,
                    "time_part1_sec": round(time.time() - t1_start, 6),
                    "time_part2_sec": 0.0,
                    "total_verify_time_sec": round(time.time() - t_start, 6),
                    "error": f"Batch aggregation requires identical messages; mismatch at index {idx}.",
                }

        eligible[idx] = True

    # If no eligible signatures remain after timestamp filter -> fail batch.
    if M0 is None:
        t1_end = time.time()
        time_part1_sec = t1_end - t1_start
        total_time_sec = time.time() - t_start
        return {
            "ok": False,
            "part1_all": False,
            "part1_results": part1_results,
            "part2": False,
            "sybil_detected": False,
            "sybil_attacks": None,
            "replay_detected": replay_detected_batch,
            "unique_signers": 0,
            "total_signatures_received": total_received,
            "duplicates_ignored": 0,
            "replays_ignored": replays_ignored,
            "time_part1_sec": round(time_part1_sec, 6),
            "time_part2_sec": 0.0,
            "total_verify_time_sec": round(total_time_sec, 6),
        }

    # Hash of common message for all eligible signatures
    Hm = _hash_to_g1(M0, g1, p)

    # Second phase of Part 1: Schnorr checks + T1-based duplicate / Sybil logic.
    zero_g1 = g1 * 0
    sum_T4 = zero_g1
    sum_neg_sx_T3 = zero_g1
    sum_c_T1 = zero_g1
    sum_c_T3 = zero_g1

    sum_sk = Bn(0)
    sum_c = Bn(0)
    sum_sx = Bn(0)
    sum_sy = Bn(0)
    sum_sd = Bn(0)

    unique_signers = 0           # effective signatures (eligible & used in batch eq)
    part1_all_ok = True
    sybil_detected = False

    # T1 tracker for duplicates when Sybil enabled
    t1_tracker = defaultdict(list)

    for idx, sig in enumerate(sig_list):
        if not eligible[idx]:
            # Already recorded in part1_results (timestamp issues, etc.)
            continue

        T1_hex = sig["T1_hex"]
        T2_hex = sig["T2_hex"]
        msg_str = sig.get("message_str", sig.get("M_hex", ""))

        short_T1 = T1_hex[:16] + "..."
        short_T2 = T2_hex[:16] + "..."

        # Track occurrences for T1-based Sybil reporting
        t1_tracker[T1_hex].append({
            "index": idx,
            "message": msg_str,
            "T1_hex": short_T1,
            "T2_hex": short_T2,
        })

        # If Sybil detection is enabled AND this T1 has been seen before, ignore
        if SYBIL_ENABLED and len(t1_tracker[T1_hex]) > 1:
            sybil_detected = True
            # Mark as duplicate-ignored
            part1_results[idx] = {
                "index": idx,
                "ok": None,
                "ignored": True,
                "reason": "duplicate_signature_T1_in_same_batch",
                "T1_hex": short_T1,
                "T2_hex": short_T2,
                "message": msg_str[:50] + "..." if len(msg_str) > 50 else msg_str,
            }
            continue

        # This is the FIRST (or sybil-disabled) signature with this T1 in the batch -> keep it
        unique_signers += 1

        # Also register globally in sybil_detector (still keyed by T2) if enabled
        if SYBIL_ENABLED:
            sig_info = {"message": msg_str, "source": source_addr, "T1_hex": T1_hex}
            sybil_detector.register_signature(T2_hex, sig_info)

        # Normal verification contributions
        T1 = _g1_from_hex(T1_hex, G)
        T2 = _g1_from_hex(T2_hex, G)
        T3 = _g1_from_hex(sig["T3_hex"], G)
        T4 = _g1_from_hex(sig["T4_hex"], G)
        c = _bn_from_hex(sig["c_hex"])
        s_k = _bn_from_hex(sig["s_k_hex"])
        s_x = _bn_from_hex(sig["s_x_hex"])
        s_d = _bn_from_hex(sig["s_d_hex"])
        s_y = _bn_from_hex(sig["s_y_hex"])

        R1_dash = (s_k * g1) + ((-c) * T2)
        R2_dash = (s_x * T2) + ((-s_d) * g1)
        c_dash = _hash_to_Zp(
            T1.export() + T2.export() + T3.export() + T4.export() +
            R1_dash.export() + R2_dash.export() + M0,
            p
        )
        ok_i = (c_dash == c)

        # Record result for this index if not set yet
        part1_results[idx] = {
            "index": idx,
            "ok": bool(ok_i),
            "ignored": False,
            "T2_hex": short_T2,
            "T1_hex": short_T1,
            "message": msg_str[:50] + "..." if len(msg_str) > 50 else msg_str,
        }
        part1_all_ok = part1_all_ok and ok_i

        # Accumulate for Part 2 (only for effective signatures)
        sum_T4 = sum_T4 + T4
        sum_neg_sx_T3 = sum_neg_sx_T3 + ((-s_x) * T3)
        sum_c_T1 = sum_c_T1 + (c * T1)
        sum_c_T3 = sum_c_T3 + (c * T3)

        sum_sk = (sum_sk + s_k) % p
        sum_c = (sum_c + c) % p
        sum_sx = (sum_sx + s_x) % p
        sum_sy = (sum_sy + s_y) % p
        sum_sd = (sum_sd + s_d) % p

    # Build sybil_attacks report from per-batch tracker (by T1) only if enabled
    sybil_attacks = []
    duplicates_ignored = 0
    if SYBIL_ENABLED:
        for T1_hex, occurrences in t1_tracker.items():
            if len(occurrences) > 1:
                sybil_detected = True
                duplicates_ignored += len(occurrences) - 1
                sybil_attacks.append({
                    "T2_hex": occurrences[0]["T2_hex"],
                    "signature_count": len(occurrences),
                    "indices": [o["index"] for o in occurrences],
                    "T1_values": [o["T1_hex"] for o in occurrences],
                    "messages": [
                        (o["message"][:50] + "...") if len(o["message"]) > 50 else o["message"]
                        for o in occurrences
                    ],
                })

    t1_end = time.time()
    time_part1_sec = t1_end - t1_start

    # ===== PART 2: Aggregated pairing check (O(1)) over effective signatures =====
    t2_start = time.time()

    if unique_signers > 0:
        left_G1 = sum_T4 + sum_neg_sx_T3 + sum_c_T1
        left_G1 = left_G1 + (sum_sk * Y) + (sum_c * g1) \
                  + ((-sum_sx) * Hm) + ((-sum_sy) * h1) + (sum_sd * h)
        right_cT3 = sum_c_T3

        e_left = G.pair(left_G1, g2)
        e_right = G.pair(right_cT3, w)
        part2_ok = (e_left == e_right)
    else:
        # No effective signatures -> failure
        part2_ok = False

    t2_end = time.time()
    time_part2_sec = t2_end - t2_start
    total_time_sec = time.time() - t_start

    # Overall decision:
    # - If Sybil enabled: duplicates_ignored > 0 => FAIL (policy).
    # - Replays_ignored do NOT automatically fail; they are just dropped.
    if SYBIL_ENABLED:
        overall_ok = part1_all_ok and part2_ok and (duplicates_ignored == 0)
    else:
        overall_ok = part1_all_ok and part2_ok

    return {
        "ok": bool(overall_ok),
        "part1_all": bool(part1_all_ok),
        "part1_results": part1_results,
        "part2": bool(part2_ok),
        "sybil_detected": sybil_detected if SYBIL_ENABLED else False,
        "sybil_attacks": sybil_attacks if (SYBIL_ENABLED and sybil_detected) else None,
        "replay_detected": replay_detected_batch,
        "unique_signers": unique_signers,
        "total_signatures_received": total_received,
        "duplicates_ignored": duplicates_ignored,
        "replays_ignored": replays_ignored,
        "time_part1_sec": round(time_part1_sec, 6),
        "time_part2_sec": round(time_part2_sec, 6),
        "total_verify_time_sec": round(total_time_sec, 6),
    }

# ============================
# Connection handler
# ============================

def handle_connection(conn, addr, verbose=True):
    try:
        payload = recv_json(conn)
        ptype = payload.get("type")

        # Ping (clock sync)
        if ptype == "ping":
            stats.record_ping()
            reply = {"ok": True, "verifier_now_ns": time.time_ns()}
            send_json(conn, reply)
            if verbose:
                print(f"[ping] {addr[0]}:{addr[1]}")
            return

        # Single signature
        if ptype == "signature":
            sigma_hex = payload.get("sigma_hex", {})
            t_start = time.time()
            result = ARA_Verify(gpk, sigma_hex, f"{addr[0]}:{addr[1]}")
            verify_time = time.time() - t_start

            reply = {
                "ok": result["verification_ok"],
                "sybil_detected": result["sybil_detected"],
                "signature_count_from_this_signer": result["signature_count_from_this_signer"],
                "replay_detected": result.get("replay_detected", False),
                "timestamp_received": result.get("timestamp_received"),
                "timestamp_expected": result.get("timestamp_expected"),
                "verifier_end_ns": time.time_ns()
            }
            if result["sybil_detected"] and SYBIL_ENABLED:
                reply["sybil_details"] = result["sybil_details"]

            send_json(conn, reply)
            stats.record_batch(
                sig_count=1,
                verify_time=verify_time,
                success=result["verification_ok"],
                sybil_detected=result["sybil_detected"]
            )

            if verbose:
                status = "OK" if result["verification_ok"] else "FAIL"
                sybil_warn = (
                    f" ⚠️ SYBIL (sig #{result['signature_count_from_this_signer']})"
                    if (SYBIL_ENABLED and result["sybil_detected"]) else ""
                )
                replay_warn = " ⏱ REPLAY" if result.get("replay_detected") else ""
                print(f"[+] {addr[0]}:{addr[1]} -> single: {status}{sybil_warn}{replay_warn} ({verify_time*1000:.2f}ms)")
            return

        # Batch signatures (MAIN USE CASE)
        if ptype == "signatures":
            sig_list = payload.get("sigma_hex", [])
            if not isinstance(sig_list, list) or not sig_list:
                send_json(conn, {"ok": False, "error": "sigma_hex must be a non-empty list"})
                return

            res = verify_batch_split(gpk, sig_list, f"{addr[0]}:{addr[1]}")
            res["count"] = len(sig_list)
            res["verifier_end_ns"] = time.time_ns()

            send_json(conn, res)

            effective_count = res.get("unique_signers", len(sig_list))
            stats.record_batch(
                sig_count=effective_count,
                verify_time=res["total_verify_time_sec"],
                success=res["ok"],
                sybil_detected=res.get("sybil_detected", False)
            )

            if verbose:
                ok_count = sum(
                    1 for r in res.get("part1_results", [])
                    if (r is not None and r.get("ok") is True and not r.get("ignored", False))
                )
                total_received = res.get("total_signatures_received", len(sig_list))
                unique_signers = res.get("unique_signers", effective_count)
                duplicates_ignored = res.get("duplicates_ignored", 0)
                replays_ignored = res.get("replays_ignored", 0)

                print(f"\n{'='*70}")
                print(f"[BATCH] {addr[0]}:{addr[1]}")
                print(f"{'='*70}")
                print(f" Signatures received: {total_received}")
                print(f" Effective signatures in batch: {unique_signers}")
                if SYBIL_ENABLED:
                    print(f" Duplicate signatures ignored (same T1): {duplicates_ignored}")
                print(f" Replay signatures ignored (bad ts): {replays_ignored}")
                print(f" Part 1 (Schnorr, effective): {ok_count}/{unique_signers} OK "
                      f"in {res['time_part1_sec']*1000:.2f}ms")
                print(f" Part 2 (Pairing over effective signatures): "
                      f"{'OK' if res['part2'] else 'FAIL'} in {res['time_part2_sec']*1000:.2f}ms")
                print(f" Total: {'✓ SUCCESS' if res['ok'] else '✗ FAILED'} "
                      f"in {res['total_verify_time_sec']*1000:.2f}ms")

                if SYBIL_ENABLED and res.get("sybil_detected"):
                    print(f"\n 🚨 SYBIL-LIKE BEHAVIOR DETECTED (duplicate T1 in batch) 🚨")
                    print(f" {'-'*66}")
                    for attack in res.get("sybil_attacks", []):
                        print(f" Signer T2 (Identity, first seen): {attack['T2_hex']}")
                        print(f" → Signatures in batch (same T1): {attack['signature_count']}")
                        print(f" → Indices in batch: {attack['indices']}")
                        print(f" → T1 values: {attack['T1_values']}")
                        print(f" {'-'*66}")
                    print(" Policy: only FIRST signature per T1 is verified; "
                          "all later ones are ignored for this batch.")
                    print(f"{'='*70}\n")
            return

        # Unknown type
        send_json(conn, {"ok": False, "error": f"Unsupported payload type: {ptype}"})

    except Exception as e:
        try:
            send_json(conn, {"ok": False, "error": str(e), "verifier_end_ns": time.time_ns()})
        except Exception:
            pass
        if verbose:
            print(f"[!] Error processing connection from {addr}: {e}")
    finally:
        conn.close()

# ============================
# Server loop
# ============================

def main():
    global SYBIL_ENABLED

    ap = argparse.ArgumentParser(
        description="ARA Batch Verifier (Raspberry Pi) with OPTIONAL Sybil Detection + Timestamp Replay Check",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
This verifier:
- Expects messages of the form: "ts||msg".
- Compares ts with EXPECTED_TS = {EXPECTED_TS_STR}; mismatches are treated as replay and ignored.

- Does batch verification with split checks:
  * Part 1: O(n) Schnorr-style checks (no pairings)
  * Part 2: O(1) aggregated pairing check

- Default mode (Sybil detection ENABLED):
  * Global T2-based tracking (signer identity).
  * Per-batch T1-based replay protection:
    - Only ONE signature per T1 participates.
    - Duplicates are ignored and cause batch failure.

- With --disable-sybil:
  * No T1/T2-based Sybil detection.
  * All timestamp-valid signatures participate.
  * Batch success depends only on cryptographic validity.
"""
    )
    ap.add_argument("--port", type=int, default=5000, help="Listen port (default 5000)")
    ap.add_argument("--host", default="0.0.0.0", help="Bind address (default 0.0.0.0)")
    ap.add_argument("--threaded", action="store_true",
                    help="Use threading for concurrent connections")
    ap.add_argument("--quiet", action="store_true", help="Reduce verbosity")
    ap.add_argument("--disable-sybil", action="store_true",
                    help="Disable all Sybil attack detection (T1 & T2)")

    args = ap.parse_args()

    if args.disable_sybil:
        SYBIL_ENABLED = False

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((args.host, args.port))

        if args.threaded:
            srv.listen(100)
            print(f"[*] Batch Verifier listening on {args.host}:{args.port} (threaded mode)")
        else:
            srv.listen(1)
            print(f"[*] Batch Verifier listening on {args.host}:{args.port} (sequential mode)")

        print(f"[*] Ready to receive signatures for batch verification")
        print(f"[*] Expected timestamp (ts in 'ts||msg'): {EXPECTED_TS_STR}")
        if SYBIL_ENABLED:
            print(f"[*] Sybil attack detection: ENABLED")
            print(f"    - Global T2 tracking (signer identity)")
            print(f"    - Per-batch T1 replay protection (duplicates ignored & force fail)\n")
        else:
            print(f"[*] Sybil attack detection: DISABLED")
            print(f"    - No T1/T2-based duplicate or Sybil handling")
            print(f"    - All timestamp-valid signatures participate in the batch equation\n")

        try:
            while True:
                conn, addr = srv.accept()

                if args.threaded:
                    thread = threading.Thread(
                        target=handle_connection,
                        args=(conn, addr, not args.quiet),
                        daemon=True
                    )
                    thread.start()
                else:
                    handle_connection(conn, addr, not args.quiet)

        except KeyboardInterrupt:
            print("\n\n[*] Shutting down...")

        summary = stats.get_summary()
        sybil_stats = sybil_detector.get_statistics() if SYBIL_ENABLED else {
            "total_signatures": 0,
            "unique_signers": 0,
            "sybil_signers": 0,
            "total_sybil_signatures": 0,
            "sybil_rate": 0.0,
            "top_offenders": []
        }

        print("\n" + "="*70)
        print("VERIFIER STATISTICS")
        print("="*70)
        print(f"Total batches processed: {summary['total_batches']}")
        print(f"Total signatures verified (effective): {summary['total_signatures']}")
        print(f"Successful batches: {summary['successful_batches']}")
        print(f"Failed batches: {summary['failed_batches']}")
        print(f"Batches with Sybil attack (only if enabled): {summary['sybil_detected_batches']}")
        print(f"Ping requests: {summary['ping_requests']}")
        if summary['total_batches'] > 0:
            print(f"\nVerification times:")
            print(f" Average: {summary['avg_verification_ms']:.2f} ms")
            print(f" Min: {summary['min_verification_ms']:.2f} ms")
            print(f" Max: {summary['max_verification_ms']:.2f} ms")

        print("\n" + "="*70)
        print("SYBIL ATTACK STATISTICS (Based on T2 tracking)")
        print("="*70)
        if SYBIL_ENABLED:
            print(f"Total signatures received: {sybil_stats['total_signatures']}")
            print(f"Unique signers (unique T2): {sybil_stats['unique_signers']}")
            print(f"Signers with duplicates: {sybil_stats['sybil_signers']}")
            print(f"Total duplicate signatures: {sybil_stats['total_sybil_signatures']}")
            if sybil_stats['total_signatures'] > 0:
                print(f"Sybil attack rate: {sybil_stats['sybil_rate']:.2f}%")
            if sybil_stats['top_offenders']:
                print(f"\nTop offenders (by signature count):")
                for i, offender in enumerate(sybil_stats['top_offenders'], 1):
                    timespan = offender['timespan_sec']
                    print(f" {i}. T2={offender['T2_hex']} → {offender['signature_count']} "
                          f"signatures over {timespan:.1f}s")
        else:
            print("Sybil detection was disabled; no T2 statistics collected.")
        print("="*70 + "\n")

if __name__ == "__main__":
    main()

