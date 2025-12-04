#!/usr/bin/env python3
# verifier_pi_batch.py
# -----------------------------------------------------
# Raspberry Pi VERIFIER with:
# - Batch verification (Schnorr + aggregated pairing)
# - Threshold + fallback to individual verification
# - Cap on examined signatures per batch
# - Sybil attack detection by T1 (optional, can disable by CLI)
# - Replay detection by (timestamp || ID) in message_str

import argparse, json, socket, struct, hashlib, time, threading
from collections import defaultdict
from bplib import bp
from bplib.bp import BpGroup
from petlib.bn import Bn

# ============================
# Policy
# ============================

# Min REQUIRED signatures per batch,
# and also max EXAMINED per batch,
# and min individually-valid signatures in fallback.
VERIFICATION_THRESHOLD = 3

# Sybil feature switch (overridden by CLI flag)
ENABLE_SYBIL = True

# ============================
# Public parameters (must match signer)
# ============================

H_HEX  = "021671ad1d26a4f36a13d7e784c30f5fb8a2dbdd520f96c68c28158317120c0194"
H1_HEX = "020d88e6287ceaf04a0686abd6bad9325dfee53a9c2606b37b62122cf611c1a4fe"
Y_HEX  = "021483d905ed81ae2a6c267bc339777fe15380e1403f924268d888e85c29b0a7e6"
W_HEX  = "15749bbf9d02337fb8cc860a256350ef4ae07eb8c148825db06911612d5c6a940bab2361cd512c36098308259502631adb4bd594c06fae47249a68b2a922459d075308a6d76f5004c268e5434059224398be1ac87c0e29b513b6ce82b50637ab158329a65a7da006e60debf1f4cfc0857de22f32568296a4c8cc310be7297677"

# ============================
# Helpers
# ============================

def clean_hex(s: str) -> str:
    if s is None:
        return ""
    return s.replace("<","").replace(">","").replace("0x","").replace(" ","").strip()

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

def _message_to_bytes(msg: str) -> bytes:
    # msg format: "ts||D"
    ts_str, D_str = msg.split("||", 1)
    ts = int(ts_str)
    D_bytes = D_str.encode("utf-8")
    ts_bytes = ts.to_bytes((ts.bit_length() + 7) // 8 or 1, "big")
    return ts_bytes + D_bytes

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

# ============================
# Build params
# ============================

G = BpGroup()
p = G.order()
g1 = G.gen1()
g2 = G.gen2()

h  = _g1_from_hex(H_HEX,  G)
h1 = _g1_from_hex(H1_HEX, G)
Y  = _g1_from_hex(Y_HEX,  G)
w  = _g2_from_hex(W_HEX,  G)

gpk = {"g1": g1, "g2": g2, "h": h, "h1": h1, "Y": Y, "w": w}

# ============================
# Replay Detection
# ============================

class ReplayDetector:
    """
    Detects replay by (ID, timestamp) extracted from message_str "ts||ID".

    - If the same (ID, ts) pair is seen again, it's marked as a replay.
    - In-memory only, no time window/persistence.
    """

    def __init__(self):
        self.lock = threading.Lock()
        # key: (ID, ts) -> info
        self.seen = {}  # (id_str, ts_int) -> {"first_seen": float, "last_seen": float, "count": int, "sources": set}
   
    def _parse_message(self, message_str: str):
        try:
            ts_str, D_str = message_str.split("||", 1)
            ts = int(ts_str)
            return ts, D_str
        except Exception:
            return None, None

    def register(self, message_str: str, source=None) -> dict:
        """
        Register a message and check if it is a replay.
        Returns:
          {
            "is_replay": bool,
            "timestamp": ts or None,
            "ID": D or None,
            "first_seen": float,
            "last_seen": float,
            "count": int,
            "reason": "ok" | "invalid_format"
          }
        """
        ts, D = self._parse_message(message_str)
        now = time.time()
        if ts is None or D is None:
            return {
                "is_replay": False,
                "timestamp": None,
                "ID": None,
                "first_seen": now,
                "last_seen": now,
                "count": 0,
                "reason": "invalid_format",
            }

        key = (D, ts)
        with self.lock:
            info = self.seen.get(key)
            if info is None:
                self.seen[key] = {
                    "first_seen": now,
                    "last_seen": now,
                    "count": 1,
                    "sources": set([source]) if source else set(),
                }
                return {
                    "is_replay": False,
                    "timestamp": ts,
                    "ID": D,
                    "first_seen": now,
                    "last_seen": now,
                    "count": 1,
                    "reason": "ok",
                }
            else:
                info["last_seen"] = now
                info["count"] += 1
                if source:
                    info["sources"].add(source)
                return {
                    "is_replay": True,
                    "timestamp": ts,
                    "ID": D,
                    "first_seen": info["first_seen"],
                    "last_seen": info["last_seen"],
                    "count": info["count"],
                    "reason": "ok",
                }

    def get_statistics(self):
        with self.lock:
            total_unique = len(self.seen)
            total_replay_pairs = sum(1 for v in self.seen.values() if v["count"] > 1)
            total_replay_events = sum(max(0, v["count"] - 1) for v in self.seen.values())
            top = sorted(
                self.seen.items(),
                key=lambda kv: kv[1]["count"],
                reverse=True,
            )[:5]
            top_offenders = []
            for (D, ts), info in top:
                if info["count"] > 1:
                    top_offenders.append({
                        "ID": D,
                        "timestamp": ts,
                        "count": info["count"],
                    })
            return {
                "unique_id_ts_pairs": total_unique,
                "replayed_pairs": total_replay_pairs,
                "total_replay_events": total_replay_events,
                "top_offenders": top_offenders,
            }

    def clear(self):
        with self.lock:
            self.seen.clear()

replay_detector = ReplayDetector()

# ============================
# Sybil Attack Detection (by T1)
# ============================

class SybilDetector:
    def __init__(self):
        self.lock = threading.Lock()
        self.t1_registry = defaultdict(list)  # T1_hex -> list of info
        self.t1_counts   = defaultdict(int)   # T1_hex -> count

    def register_signature(self, T1_hex: str, sig_info: dict):
        with self.lock:
            self.t1_counts[T1_hex] += 1
            self.t1_registry[T1_hex].append({
                "timestamp": time.time(),
                "message": sig_info.get("message", ""),
                "source": sig_info.get("source", "unknown"),
            })
            return self.t1_counts[T1_hex]

    def check_sybil(self, T1_hex: str) -> dict:
        with self.lock:
            count   = self.t1_counts.get(T1_hex, 0)
            history = self.t1_registry.get(T1_hex, [])
            return {
                "is_sybil": count > 1,
                "total_count": count,
                "previous_signatures": history[:-1] if count > 1 else [],
            }

    def get_statistics(self):
        with self.lock:
            total_unique_signers = len(self.t1_registry)
            sybil_signers = sum(1 for c in self.t1_counts.values() if c > 1)
            total_sybil_sigs = sum(c - 1 for c in self.t1_counts.values() if c > 1)
            top_offenders = sorted(
                [(t1, c) for t1, c in self.t1_counts.items() if c > 1],
                key=lambda x: x[1],
                reverse=True
            )[:5]
            return {
                "unique_signers": total_unique_signers,
                "sybil_signers": sybil_signers,
                "total_sybil_signatures": total_sybil_sigs,
                "top_offenders": [
                    {"T1_hex": t1[:16] + "...", "signature_count": c}
                    for t1, c in top_offenders
                ],
            }

    def clear(self):
        with self.lock:
            self.t1_registry.clear()
            self.t1_counts.clear()

sybil_detector = SybilDetector()

# ============================
# Stats
# ============================

class VerifierStats:
    def __init__(self):
        self.lock = threading.Lock()
        self.total_batches = 0
        self.total_signatures = 0  # examined signatures
        self.successful_batches = 0
        self.failed_batches = 0
        self.sybil_detected_batches = 0
        self.ping_count = 0
        self.verification_times = []

    def record_batch(self, sig_count, verify_time, success, sybil_detected=False):
        with self.lock:
            self.total_batches += 1
            self.total_signatures += sig_count
            if success:
                self.successful_batches += 1
            else:
                self.failed_batches += 1
            if sybil_detected:
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
# Single-signature verify
# ============================

def ARA_Verify(gpk, sigma_hex: dict, source_addr=None) -> dict:
    T1_hex = sigma_hex["T1_hex"]
    T1 = _g1_from_hex(T1_hex, G)
    T2 = _g1_from_hex(sigma_hex["T2_hex"], G)
    T3 = _g1_from_hex(sigma_hex["T3_hex"], G)
    T4 = _g1_from_hex(sigma_hex["T4_hex"], G)
    c  = _bn_from_hex(sigma_hex["c_hex"])
    s_k = _bn_from_hex(sigma_hex["s_k_hex"])
    s_x = _bn_from_hex(sigma_hex["s_x_hex"])
    s_d = _bn_from_hex(sigma_hex["s_d_hex"])
    s_y = _bn_from_hex(sigma_hex["s_y_hex"])

    if "message_str" in sigma_hex and sigma_hex["message_str"]:
        M = _message_to_bytes(sigma_hex["message_str"])
        msg_str = sigma_hex["message_str"]
    else:
        M = bytes.fromhex(clean_hex(sigma_hex["M_hex"]))
        msg_str = sigma_hex.get("M_hex", "")

    # Sybil registration (by T1)
    if ENABLE_SYBIL:
        sig_info = {"message": msg_str, "source": source_addr}
        count = sybil_detector.register_signature(T1_hex, sig_info)
        sybil_info = sybil_detector.check_sybil(T1_hex)
    else:
        count = 1
        sybil_info = {"is_sybil": False, "total_count": 1, "previous_signatures": []}

    # Replay detection (by "ts||ID" in msg_str)
    if "||" in msg_str:
        replay_info = replay_detector.register(msg_str, source_addr)
    else:
        replay_info = {
            "is_replay": False,
            "timestamp": None,
            "ID": None,
            "first_seen": time.time(),
            "last_seen": time.time(),
            "count": 0,
            "reason": "invalid_format",
        }

    g1 = gpk['g1']; g2 = gpk['g2']; h = gpk['h']; h1 = gpk['h1']; w = gpk['w']; Y = gpk['Y']
    Hm = _hash_to_g1(M, g1, p)

    R1_dash = (s_k * g1) + ((-c) * T2)
    R2_dash = (s_x * T2) + ((-s_d) * g1)
    c_dash = _hash_to_Zp(
        T1.export()+T2.export()+T3.export()+T4.export()+
        R1_dash.export()+R2_dash.export()+M, p
    )

    KK  = T4 + (-s_x) * T3 + c * T1 + s_k * Y + c * g1 \
          + (-s_x) * Hm + (-s_y) * h1 + s_d * h
    e_KK_g2 = G.pair(KK, g2)
    e_cT3_w = G.pair(c * T3, w)

    verification_ok = (c_dash == c) and (e_KK_g2 == e_cT3_w)

    # IMPORTANT:
    # For now, replay detection does NOT automatically flip verification_ok.
    # You can enforce that later at policy level if you want:
    # if replay_info["is_replay"]:
    #     verification_ok = False

    return {
        "verification_ok": bool(verification_ok),
        "sybil_detected": sybil_info["is_sybil"],
        "signature_count_from_this_signer": count,
        "sybil_details": sybil_info if sybil_info["is_sybil"] else None,
        "replay_detected": replay_info["is_replay"],
        "replay_details": replay_info if replay_info["is_replay"] else None,
    }

# ============================
# Batch verify with threshold + fallback
# ============================

def verify_batch_split(gpk, sig_list, source_addr=None):
    """
    Behavior:
    - If len(sig_list) < VERIFICATION_THRESHOLD:
        * Reject immediately (not enough signatures).
    - If len(sig_list) > VERIFICATION_THRESHOLD:
        * Only first VERIFICATION_THRESHOLD signatures are examined (batch + fallback).
    - Fast path:
        * Part 1: Schnorr (no pairings).
        * Part 2: one aggregated pairing.
    - Fallback:
        * Triggered ONLY IF:
            - all Schnorr checks pass (part1_all_ok == True), AND
            - aggregated pairing fails (part2_ok == False).
        * Then individually verify EVERY examined signature (full pairing).
        * Batch OK <=> individually_valid >= VERIFICATION_THRESHOLD.
    """
    t_start = time.time()
    g1 = gpk['g1']; g2 = gpk['g2']; h = gpk['h']; h1 = gpk['h1']; w = gpk['w']; Y = gpk['Y']

    total_received = len(sig_list)

    # ---- MINIMUM required signatures check ----
    if total_received < VERIFICATION_THRESHOLD:
        total_time_sec = time.time() - t_start
        return {
            "ok": False,
            "part1_all": False,
            "part1_results": [],
            "part2": False,
            "sybil_detected": False,
            "sybil_attacks": None,
            "replay_detected": False,
            "replay_attacks": None,
            "unique_signers": 0,
            "threshold": VERIFICATION_THRESHOLD,
            "fallback_used": False,
            "individually_valid": 0,
            "examined_signatures": total_received,
            "ignored_signatures": 0,
            "error": (
                f"not enough signatures for verification: "
                f"required {VERIFICATION_THRESHOLD}, got {total_received}"
            ),
            "time_part1_sec": 0.0,
            "time_part2_sec": 0.0,
            "total_verify_time_sec": round(total_time_sec, 6),
        }

    # ---- Cap to threshold (max examined) ----
    if total_received > VERIFICATION_THRESHOLD:
        examined_sigs = sig_list[:VERIFICATION_THRESHOLD]
        ignored_signatures = total_received - VERIFICATION_THRESHOLD
    else:
        examined_sigs = sig_list
        ignored_signatures = 0

    # Helper: get message bytes
    def get_M(sig):
        if "message_str" in sig and sig["message_str"]:
            return _message_to_bytes(sig["message_str"])
        return bytes.fromhex(clean_hex(sig["M_hex"]))

    # Require same message across examined signatures for aggregation
    M0 = get_M(examined_sigs[0])
    for i, s in enumerate(examined_sigs[1:], start=1):
        if get_M(s) != M0:
            total_time_sec = time.time() - t_start
            return {
                "ok": False,
                "part1_all": False,
                "part1_results": [],
                "part2": False,
                "sybil_detected": False,
                "sybil_attacks": None,
                "replay_detected": False,
                "replay_attacks": None,
                "unique_signers": 0,
                "threshold": VERIFICATION_THRESHOLD,
                "fallback_used": False,
                "individually_valid": 0,
                "examined_signatures": len(examined_sigs),
                "ignored_signatures": ignored_signatures,
                "error": (
                    f"Batch aggregation requires identical messages; mismatch at index {i}."
                ),
                "time_part1_sec": 0.0,
                "time_part2_sec": 0.0,
                "total_verify_time_sec": round(total_time_sec, 6),
            }

    Hm = _hash_to_g1(M0, g1, p)

    # ----- Part 1: Schnorr checks -----
    t1_start = time.time()
    part1_results = []
    part1_all_ok = True

    zero_g1 = g1 * 0
    sum_T4        = zero_g1
    sum_neg_sx_T3 = zero_g1
    sum_c_T1      = zero_g1
    sum_c_T3      = zero_g1

    sum_sk = Bn(0)
    sum_c  = Bn(0)
    sum_sx = Bn(0)
    sum_sy = Bn(0)
    sum_sd = Bn(0)

    t1_tracker = defaultdict(list)
    replay_tracker = []  # per-signature replay info

    for idx, sig in enumerate(examined_sigs):
        T1_hex = sig["T1_hex"]
        T1 = _g1_from_hex(T1_hex, G)
        T2 = _g1_from_hex(sig["T2_hex"], G)
        T3 = _g1_from_hex(sig["T3_hex"], G)
        T4 = _g1_from_hex(sig["T4_hex"], G)
        c  = _bn_from_hex(sig["c_hex"])
        s_k = _bn_from_hex(sig["s_k_hex"])
        s_x = _bn_from_hex(sig["s_x_hex"])
        s_d = _bn_from_hex(sig["s_d_hex"])
        s_y = _bn_from_hex(sig["s_y_hex"])

        msg_str = sig.get("message_str", sig.get("M_hex", ""))
        t1_tracker[T1_hex].append({"index": idx, "message": msg_str})

        # Sybil registration
        if ENABLE_SYBIL:
            sig_info = {"message": msg_str, "source": source_addr}
            count = sybil_detector.register_signature(T1_hex, sig_info)
        else:
            count = 1

        # Replay registration
        if "||" in msg_str:
            replay_info = replay_detector.register(msg_str, source_addr)
        else:
            replay_info = {
                "is_replay": False,
                "timestamp": None,
                "ID": None,
                "first_seen": time.time(),
                "last_seen": time.time(),
                "count": 0,
                "reason": "invalid_format",
            }
        replay_tracker.append({
            "index": idx,
            "is_replay": replay_info["is_replay"],
            "ID": replay_info["ID"],
            "timestamp": replay_info["timestamp"],
            "count": replay_info["count"],
        })

        # Schnorr part
        R1_dash = (s_k * g1) + ((-c) * T2)
        R2_dash = (s_x * T2) + ((-s_d) * g1)
        c_dash = _hash_to_Zp(
            T1.export()+T2.export()+T3.export()+T4.export()+
            R1_dash.export()+R2_dash.export()+M0, p
        )
        ok_i = (c_dash == c)

        part1_results.append({
            "index": idx,
            "ok": bool(ok_i),
            "T1_hex": T1_hex[:16] + "...",
            "signature_count_from_this_signer": count,
            "replay": replay_info["is_replay"],
        })
        part1_all_ok = part1_all_ok and ok_i

        # accumulate for aggregated pairing
        sum_T4        = sum_T4 + T4
        sum_neg_sx_T3 = sum_neg_sx_T3 + ((-s_x) * T3)
        sum_c_T1      = sum_c_T1 + (c * T1)
        sum_c_T3      = sum_c_T3 + (c * T3)

        sum_sk = (sum_sk + s_k) % p
        sum_c  = (sum_c  + c)   % p
        sum_sx = (sum_sx + s_x) % p
        sum_sy = (sum_sy + s_y) % p
        sum_sd = (sum_sd + s_d) % p

    # local sybil detection
    sybil_detected = False
    sybil_attacks = []
    if ENABLE_SYBIL:
        for T1_hex, occ in t1_tracker.items():
            if len(occ) > 1:
                sybil_detected = True
                sybil_attacks.append({
                    "T1_hex": T1_hex[:16] + "...",
                    "signature_count": len(occ),
                    "indices": [o["index"] for o in occ],
                    "messages": [
                        o["message"][:50]+"..." if len(o["message"]) > 50 else o["message"]
                        for o in occ
                    ],
                })

    # local replay detection for this batch
    replay_detected = any(r["is_replay"] for r in replay_tracker)
    replay_attacks = None
    if replay_detected:
        # group replays by (ID, timestamp)
        replay_map = defaultdict(list)  # (ID, ts) -> list of indices
        for r in replay_tracker:
            if r["is_replay"] and r["ID"] is not None and r["timestamp"] is not None:
                key = (r["ID"], r["timestamp"])
                replay_map[key].append(r["index"])
        replay_attacks = []
        for (ID, ts), indices in replay_map.items():
            replay_attacks.append({
                "ID": ID,
                "timestamp": ts,
                "indices": indices,
            })

    t1_end = time.time()
    time_part1_sec = t1_end - t1_start

    # ----- Part 2: aggregated pairing -----
    t2_start = time.time()

    left_G1 = sum_T4 + sum_neg_sx_T3 + sum_c_T1
    left_G1 = left_G1 + (sum_sk * Y) + (sum_c * g1) \
              + ((-sum_sx) * Hm) + ((-sum_sy) * h1) + (sum_sd * h)
    right_cT3 = sum_c_T3

    e_left  = G.pair(left_G1, g2)
    e_right = G.pair(right_cT3, w)
    part2_ok = (e_left == e_right)

    t2_end = time.time()
    time_part2_sec = t2_end - t2_start

    total_time_sec = time.time() - t_start

    # ----- Fallback: individual verification if fast batch fails -----
    fallback_used = False
    individually_valid = 0

    # IMPORTANT: fallback only if part1_all_ok and part2 fails
    if part1_all_ok and part2_ok:
        overall_ok = True
    elif (not part1_all_ok):
        overall_ok = False
    else:
        # part1_all_ok == True and part2_ok == False -> fallback
        fallback_used = True
        individually_valid = 0

        for sig in examined_sigs:
            T1_hex = sig["T1_hex"]
            T1 = _g1_from_hex(T1_hex, G)
            T2 = _g1_from_hex(sig["T2_hex"], G)
            T3 = _g1_from_hex(sig["T3_hex"], G)
            T4 = _g1_from_hex(sig["T4_hex"], G)
            c  = _bn_from_hex(sig["c_hex"])
            s_k = _bn_from_hex(sig["s_k_hex"])
            s_x = _bn_from_hex(sig["s_x_hex"])
            s_d = _bn_from_hex(sig["s_d_hex"])
            s_y = _bn_from_hex(sig["s_y_hex"])

            if "message_str" in sig and sig["message_str"]:
                Mi = _message_to_bytes(sig["message_str"])
            else:
                Mi = bytes.fromhex(clean_hex(sig["M_hex"]))

            Hm_i = _hash_to_g1(Mi, g1, p)

            R1_dash_i = (s_k * g1) + ((-c) * T2)
            R2_dash_i = (s_x * T2) + ((-s_d) * g1)
            c_dash_i = _hash_to_Zp(
                T1.export()+T2.export()+T3.export()+T4.export()+
                R1_dash_i.export()+R2_dash_i.export()+Mi, p
            )

            KK_i = T4 + (-s_x) * T3 + c * T1 + s_k * Y + c * g1 \
                   + (-s_x) * Hm_i + (-s_y) * h1 + s_d * h
            e_KK_g2_i = G.pair(KK_i, g2)
            e_cT3_w_i = G.pair(c * T3, w)

            if (c_dash_i == c) and (e_KK_g2_i == e_cT3_w_i):
                individually_valid += 1

        overall_ok = (individually_valid >= VERIFICATION_THRESHOLD)

    unique_signers = len(t1_tracker)

    return {
        "ok": bool(overall_ok),
        "part1_all": bool(part1_all_ok),
        "part1_results": part1_results,
        "part2": bool(part2_ok),
        "sybil_detected": sybil_detected,
        "sybil_attacks": sybil_attacks if sybil_detected else None,
        "replay_detected": replay_detected,
        "replay_attacks": replay_attacks if replay_detected else None,
        "unique_signers": unique_signers,
        "threshold": VERIFICATION_THRESHOLD,
        "fallback_used": fallback_used,
        "individually_valid": individually_valid,
        "examined_signatures": len(examined_sigs),
        "ignored_signatures": ignored_signatures,
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

        if ptype == "ping":
            stats.record_ping()
            reply = {"ok": True, "verifier_now_ns": time.time_ns()}
            send_json(conn, reply)
            if verbose:
                print(f"[ping] {addr[0]}:{addr[1]}")
            return

        if ptype == "signature":
            sigma_hex = payload.get("sigma_hex", {})
            t_start = time.time()
            result = ARA_Verify(gpk, sigma_hex, f"{addr[0]}:{addr[1]}")
            verify_time = time.time() - t_start

            reply = {
                "ok": result["verification_ok"],
                "sybil_detected": result["sybil_detected"],
                "signature_count_from_this_signer": result["signature_count_from_this_signer"],
                "replay_detected": result["replay_detected"],
                "verifier_end_ns": time.time_ns(),
            }
            if result["sybil_detected"]:
                reply["sybil_details"] = result["sybil_details"]
            if result["replay_detected"]:
                reply["replay_details"] = result["replay_details"]
            send_json(conn, reply)

            stats.record_batch(1, verify_time, result["verification_ok"], result["sybil_detected"])

            if verbose:
                status = "OK" if result["verification_ok"] else "FAIL"
                sybil_warn = ""
                if ENABLE_SYBIL and result["sybil_detected"]:
                    sybil_warn = f" ⚠️ SYBIL (sig #{result['signature_count_from_this_signer']})"
                replay_warn = " ⚠️ REPLAY" if result["replay_detected"] else ""
                print(f"[+] {addr[0]}:{addr[1]} -> single: {status}{sybil_warn}{replay_warn} ({verify_time*1000:.2f}ms)")
            return

        if ptype == "signatures":
            sig_list = payload.get("sigma_hex", [])
            if not isinstance(sig_list, list) or not sig_list:
                send_json(conn, {"ok": False, "error": "sigma_hex must be a non-empty list"})
                return

            res = verify_batch_split(gpk, sig_list, f"{addr[0]}:{addr[1]}")
            res["count"] = len(sig_list)
            res["verifier_end_ns"] = time.time_ns()
            send_json(conn, res)

            stats.record_batch(
                res.get("examined_signatures", len(sig_list)),
                res["total_verify_time_sec"],
                res["ok"],
                res.get("sybil_detected", False),
            )

            if verbose:
                ok_count = sum(1 for r in res.get("part1_results", []) if r.get("ok"))
                print(f"\n{'='*70}")
                print(f"[BATCH] {addr[0]}:{addr[1]}")
                print(f"{'='*70}")
                print(f"  Signatures received:      {len(sig_list)}")
                print(f"  Signatures examined:      {res.get('examined_signatures', 0)}")
                print(f"  Signatures ignored:       {res.get('ignored_signatures', 0)}")
                print(f"  Unique signers (T1):      {res.get('unique_signers', 0)}")
                print(f"  Threshold:                {res.get('threshold')}")

                if "error" in res and res["error"]:
                    print(f"  Error: {res['error']}")

                if res.get("fallback_used"):
                    print("  Fast batch verification FAILED (pairing mismatch) -> launching individual per-signature verification.")
                    print(f"  Individually valid signatures: {res.get('individually_valid', 0)}/"
                          f"{res.get('examined_signatures', 0)}")
                else:
                    if res.get("ok"):
                        print("  Fast batch verification SUCCEEDED (no fallback needed).")
                    else:
                        if not res.get("error"):
                            print("  Fast batch verification FAILED (Schnorr part) -> no fallback, batch rejected.")

                print(f"  Part 1 (Schnorr): {ok_count}/{res.get('examined_signatures', 0)} OK "
                      f"in {res['time_part1_sec']*1000:.2f}ms")
                print(f"  Part 2 (Pairing): {'OK' if res['part2'] else 'FAIL'} "
                      f"in {res['time_part2_sec']*1000:.2f}ms")
                print(f"  Total: {'✓ SUCCESS' if res['ok'] else '✗ FAILED'} "
                      f"in {res['total_verify_time_sec']*1000:.2f}ms")

                if ENABLE_SYBIL and res.get("sybil_detected"):
                    print("\n  ⚠️ SYBIL ATTACK DETECTED ⚠️")
                    print("  " + "-"*66)
                    for attack in res.get("sybil_attacks", []):
                        print(f"  Signer T1: {attack['T1_hex']}")
                        print(f"    → Generated {attack['signature_count']} signatures (among examined)")
                        print(f"    → Indices in examined batch: {attack['indices']}")
                    print("  " + "-"*66)

                if res.get("replay_detected"):
                    print("\n  ⚠️ REPLAY DETECTED ⚠️")
                    print("  " + "-"*66)
                    for attack in res.get("replay_attacks", []) or []:
                        print(f"  ID: {attack['ID']}, ts={attack['timestamp']}")
                        print(f"    → Replay indices in examined batch: {attack['indices']}")
                    print("  " + "-"*66)

                print(f"{'='*70}\n")
            return

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
    ap = argparse.ArgumentParser(
        description="ARA Batch Verifier with threshold + fallback + Sybil + Replay detection",
    )
    ap.add_argument("--port", type=int, default=5000, help="Listen port (default 5000)")
    ap.add_argument("--host", default="0.0.0.0", help="Bind address (default 0.0.0.0)")
    ap.add_argument("--threaded", action="store_true", help="Use threading")
    ap.add_argument("--quiet", action="store_true", help="Reduce verbosity")
    ap.add_argument(
        "--disable-sybil",
        action="store_true",
        help="Disable Sybil attack detection and global T1 tracking",
    )
    args = ap.parse_args()

    global ENABLE_SYBIL
    ENABLE_SYBIL = not args.disable_sybil

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((args.host, args.port))

        if args.threaded:
            srv.listen(100)
            print(f"[*] Batch Verifier listening on {args.host}:{args.port} (threaded)")
        else:
            srv.listen(1)
            print(f"[*] Batch Verifier listening on {args.host}:{args.port} (sequential)")

        print(f"[*] Ready to receive signatures for batch verification")
        print(f"[*] Verification threshold: {VERIFICATION_THRESHOLD} signatures")
        print(f"[*] Sybil attack detection: {'ENABLED' if ENABLE_SYBIL else 'DISABLED'}\n")

        try:
            while True:
                conn, addr = srv.accept()
                if args.threaded:
                    t = threading.Thread(
                        target=handle_connection,
                        args=(conn, addr, not args.quiet),
                        daemon=True,
                    )
                    t.start()
                else:
                    handle_connection(conn, addr, not args.quiet)
        except KeyboardInterrupt:
            print("\n\n[*] Shutting down...")

            summary = stats.get_summary()
            sybil_stats = sybil_detector.get_statistics()
            replay_stats = replay_detector.get_statistics()

            print("\n" + "="*70)
            print("VERIFIER STATISTICS")
            print("="*70)
            print(f"Total batches processed:   {summary['total_batches']}")
            print(f"Total signatures examined: {summary['total_signatures']}")
            print(f"Successful batches:        {summary['successful_batches']}")
            print(f"Failed batches:            {summary['failed_batches']}")
            print(f"Batches with Sybil attack: {summary['sybil_detected_batches']}")
            print(f"Ping requests:             {summary['ping_requests']}")
            if summary['total_batches'] > 0:
                print("\nVerification times:")
                print(f"  Average: {summary['avg_verification_ms']:.2f} ms")
                print(f"  Min:     {summary['min_verification_ms']:.2f} ms")
                print(f"  Max:     {summary['max_verification_ms']:.2f} ms")

            print("\n" + "="*70)
            print("SYBIL ATTACK STATISTICS")
            print("="*70)
            print(f"Unique signers seen:       {sybil_stats['unique_signers']}")
            print(f"Signers with duplicates:   {sybil_stats['sybil_signers']}")
            print(f"Total duplicate signatures:{sybil_stats['total_sybil_signatures']}")
            if sybil_stats['top_offenders']:
                print("\nTop offenders:")
                for i, off in enumerate(sybil_stats['top_offenders'], 1):
                    print(f"  {i}. T1={off['T1_hex']} → {off['signature_count']} signatures")
            print("="*70 + "\n")

            print("\n" + "="*70)
            print("REPLAY STATISTICS")
            print("="*70)
            print(f"Unique (ID, ts) pairs seen:     {replay_stats['unique_id_ts_pairs']}")
            print(f"(ID, ts) pairs with replays:    {replay_stats['replayed_pairs']}")
            print(f"Total replay events:            {replay_stats['total_replay_events']}")
            if replay_stats['top_offenders']:
                print("\nTop replay offenders:")
                for i, off in enumerate(replay_stats['top_offenders'], 1):
                    print(f"  {i}. ID={off['ID']} ts={off['timestamp']} → {off['count']} times")
            print("="*70 + "\n")

if __name__ == "__main__":
    main()

