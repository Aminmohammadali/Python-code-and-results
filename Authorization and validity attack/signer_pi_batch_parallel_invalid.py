#!/usr/bin/env python3
# signer_pi_batch_parallel.py
# -----------------------------------------------------
# Parallel signature generation with INVALID signature injection
# - Generates N-1 valid signatures + 1 invalid signature (random values)
# - Invalid signature position can be specified or randomized

import argparse, json, socket, struct, hashlib, sys, time, random
from bplib import bp
from bplib.bp import BpGroup
from petlib.bn import Bn
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
import multiprocessing as mp

# ============================
# Predefined public parameters
# ============================
H_HEX  = "021671ad1d26a4f36a13d7e784c30f5fb8a2dbdd520f96c68c28158317120c0194"
H1_HEX = "020d88e6287ceaf04a0686abd6bad9325dfee53a9c2606b37b62122cf611c1a4fe"
Y_HEX  = "021483d905ed81ae2a6c267bc339777fe15380e1403f924268d888e85c29b0a7e6"
W_HEX  = "15749bbf9d02337fb8cc860a256350ef4ae07eb8c148825db06911612d5c6a940bab2361cd512c36098308259502631adb4bd594c06fae47249a68b2a922459d075308a6d76f5004c268e5434059224398be1ac87c0e29b513b6ce82b50637ab158329a65a7da006e60debf1f4cfc0857de22f32568296a4c8cc310be7297677"

# ============================
# Predefined member secrets
# ============================
A_I_HEX = "03104a3fdf718f364afa819caec046cef6643932d24fb658d245598ae462b888ca"
X_I_HEX = "22b42a5548c529ed47667df4ebcc7a28f6e91ab6b06ec6bf348aee196a889050"
Y_I_HEX = "1906f3322b39de69420d399b3497709bd2b4ec776b5a05ce43ef6345e3c2229c"

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

def _bn_from_hex(h: str) -> Bn:
    return Bn.from_binary(bytes.fromhex(clean_hex(h)))

def _hash_to_Zp(data: bytes, p: Bn) -> Bn:
    digest = hashlib.sha256(data).digest()
    n = int.from_bytes(digest, "big")
    n_bytes = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
    return Bn.from_binary(n_bytes) % p

def _hash_to_g1(data: bytes, g1, p):
    return _hash_to_Zp(data, p) * g1

def _message_to_bytes(msg: str) -> bytes:
    ts_str, D_str = msg.split("||", 1)
    ts = int(ts_str)
    D_bytes = D_str.encode("utf-8")
    ts_bytes = ts.to_bytes((ts.bit_length() + 7) // 8 or 1, "big")
    return ts_bytes + D_bytes

def _send_json(sock: socket.socket, obj: dict):
    data = json.dumps(obj).encode("utf-8")
    sock.sendall(struct.pack("!I", len(data)))
    sock.sendall(data)

def _recv_json(sock: socket.socket) -> dict:
    hdr = sock.recv(4)
    if len(hdr) < 4:
        raise ConnectionError("Short read on header")
    (length,) = struct.unpack("!I", hdr)
    buf = b""
    while len(buf) < length:
        chunk = sock.recv(length - len(buf))
        if not chunk:
            raise ConnectionError("Short read on payload")
        buf += chunk
    return json.loads(buf.decode("utf-8"))

# ============================
# Initialize crypto params (for worker processes)
# ============================

def init_worker():
    """Initialize crypto parameters in each worker process"""
    global G, p, g1, g2, h, h1, Y, w, gpk, A_i, x_i, y_i, gsk_i
    
    G = BpGroup()
    p = G.order()
    g1 = G.gen1()
    g2 = G.gen2()

    h  = _g1_from_hex(H_HEX,  G)
    h1 = _g1_from_hex(H1_HEX, G)
    Y  = _g1_from_hex(Y_HEX,  G)
    w  = _g2_from_hex(W_HEX,  G)

    gpk = {"g1": g1, "g2": g2, "h": h, "h1": h1, "Y": Y, "w": w}

    A_i = _g1_from_hex(A_I_HEX, G)
    x_i = _bn_from_hex(X_I_HEX)
    y_i = _bn_from_hex(Y_I_HEX)
    gsk_i = {"A_i": A_i, "x_i": x_i, "y_i": y_i}

# Initialize for main process
init_worker()

# ============================
# Signing (single signature)
# ============================

def ARA_Sign_single(message_str: str):
    """Generate a single VALID signature"""
    g1_, h_, h1_, Y_ = gpk['g1'], gpk['h'], gpk['h1'], gpk['Y']
    A_i_, x_i_, y_i_ = gsk_i['A_i'], gsk_i['x_i'], gsk_i['y_i']

    M = _message_to_bytes(message_str)
    def r(): return Bn.random(p - 1) + 1
    k   = r()
    r_k = r()
    r_x = r()
    r_d = r()
    r_y = r()

    delta1 = (x_i_ * k) % p

    Hm = _hash_to_g1(M, g1_, p)
    T1 = x_i_ * Hm
    T2 = k * g1_
    T3 = A_i_ + (k * h_)
    T4 = r_x * (T3 + Hm) + (-r_d * h_) + (-r_k * Y_) + (r_y * h1_)

    R1 = r_k * g1_
    R2 = (r_x * T2) + (-r_d * g1_)

    c = _hash_to_Zp(
        T1.export() + T2.export() + T3.export() + T4.export() +
        R1.export() + R2.export() + M,
        p
    )

    s_k = (r_k + c * k)            % p
    s_x = (r_x + c * x_i_)         % p
    s_d = (r_d + c * delta1)       % p
    s_y = (r_y + c * y_i_)         % p

    return {
        "T1_hex": T1.export().hex(),
        "T2_hex": T2.export().hex(),
        "T3_hex": T3.export().hex(),
        "T4_hex": T4.export().hex(),
        "c_hex":  c.binary().hex(),
        "s_k_hex": s_k.binary().hex(),
        "s_x_hex": s_x.binary().hex(),
        "s_d_hex": s_d.binary().hex(),
        "s_y_hex": s_y.binary().hex(),
        "M_hex": M.hex(),
        "message_str": message_str
    }

def ARA_Sign_invalid(message_str: str):
    """Generate an INVALID signature with random values"""
    g1_ = gpk['g1']
    M = _message_to_bytes(message_str)
    
    # Generate random group elements and scalars (INVALID signature)
    def r(): return Bn.random(p - 1) + 1
    
    T1 = r() * g1_  # Random point
    T2 = r() * g1_  # Random point
    T3 = r() * g1_  # Random point
    T4 = r() * g1_  # Random point
    
    # Random scalars
    c   = r()
    s_k = r()
    s_x = r()
    s_d = r()
    s_y = r()

    return {
        "T1_hex": T1.export().hex(),
        "T2_hex": T2.export().hex(),
        "T3_hex": T3.export().hex(),
        "T4_hex": T4.export().hex(),
        "c_hex":  c.binary().hex(),
        "s_k_hex": s_k.binary().hex(),
        "s_x_hex": s_x.binary().hex(),
        "s_d_hex": s_d.binary().hex(),
        "s_y_hex": s_y.binary().hex(),
        "M_hex": M.hex(),
        "message_str": message_str,
        "INVALID": True  # Mark as invalid for debugging
    }

def worker_sign(idx_and_message_and_invalid):
    """Worker function for parallel signature generation"""
    idx, message, make_invalid = idx_and_message_and_invalid
    if make_invalid:
        return idx, ARA_Sign_invalid(message)
    else:
        return idx, ARA_Sign_single(message)

# ============================
# Parallel signature generation with invalid injection
# ============================

def generate_signatures_parallel(count: int, message_str: str, workers: int = None, 
                                 method: str = "thread", invalid_count: int = 1,
                                 invalid_positions: list = None):
    """
    Generate signatures in parallel with some invalid signatures.

    Args:
        count: Total number of signatures to generate
        message_str: Message to sign
        workers: Number of parallel workers
        method: 'thread' or 'process'
        invalid_count: Number of invalid signatures to inject
        invalid_positions: Specific positions for invalid signatures (0-indexed)
                          If None, positions are randomly chosen

    Returns:
        signatures: list of signatures (mix of valid and invalid)
        gen_time_sec: wall time to generate the batch
        invalid_indices: list of indices where invalid signatures were placed
    """
    if workers is None:
        workers = min(count, mp.cpu_count())
    
    # Determine positions for invalid signatures
    if invalid_positions is None:
        invalid_positions = random.sample(range(count), min(invalid_count, count))
    else:
        invalid_positions = [pos for pos in invalid_positions if 0 <= pos < count]
    
    invalid_set = set(invalid_positions)
    
    print(f"[*] Generating {count} signatures using {workers} {method} workers...")
    print(f"[!] Injecting {len(invalid_positions)} INVALID signature(s) at position(s): {sorted(invalid_positions)}")
    
    # Prepare work items: (index, message, should_be_invalid)
    work_items = [(i, message_str, i in invalid_set) for i in range(count)]
    
    t_start = time.time()
    
    if method == "process":
        with ProcessPoolExecutor(max_workers=workers, initializer=init_worker) as executor:
            results = list(executor.map(worker_sign, work_items))
    else:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            results = list(executor.map(worker_sign, work_items))
    
    t_end = time.time()
    gen_time_sec = t_end - t_start

    # Sort by index to keep deterministic order
    results.sort(key=lambda x: x[0])
    signatures = [sig for idx, sig in results]
    
    if gen_time_sec > 0:
        rate = count / gen_time_sec
    else:
        rate = float("inf")
    
    valid_count = count - len(invalid_positions)
    print(f"[✓] Batch generated in {gen_time_sec:.3f}s ({rate:.1f} sigs/sec)")
    print(f"    → {valid_count} VALID signatures")
    print(f"    → {len(invalid_positions)} INVALID signatures")
    
    return signatures, gen_time_sec, sorted(invalid_positions)

# ============================
# Clock sync
# ============================

def do_clock_sync(host: str, port: int, samples: int = 10, timeout: float = 5.0) -> int:
    """Estimate (verifier_clock - signer_clock) in ns"""
    offsets = []
    for i in range(samples):
        try:
            with socket.create_connection((host, port), timeout=timeout) as s:
                t_send_ns = time.time_ns()
                _send_json(s, {"type": "ping"})
                reply = _recv_json(s)
                t_recv_ns = time.time_ns()

                if not isinstance(reply, dict) or not reply.get("ok", False):
                    continue

                if "verifier_now_ns" not in reply:
                    continue

                t_ver_ns = int(reply["verifier_now_ns"])
                theta = t_ver_ns - ((t_send_ns + t_recv_ns) // 2)
                offsets.append(theta)

        except Exception:
            continue

    if not offsets:
        raise RuntimeError("Clock sync failed: no valid pong replies")
    offsets.sort()
    return offsets[len(offsets)//2]

# ============================
# Main
# ============================

def main():
    ap = argparse.ArgumentParser(
        description="Parallel Signature Generation with Invalid Signature Injection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example usage:
  # Generate 10 signatures with 1 invalid (random position):
  python3 signer_pi_batch_parallel.py --host 192.168.1.100 --count 10 --invalid 1

  # Generate 10 signatures with invalid at specific position (index 5):
  python3 signer_pi_batch_parallel.py --host 192.168.1.100 --count 10 --invalid-pos 5

  # Generate 100 signatures with 5 invalid at random positions:
  python3 signer_pi_batch_parallel.py --host 192.168.1.100 --count 100 --invalid 5

  # Multiple invalid at specific positions:
  python3 signer_pi_batch_parallel.py --host 192.168.1.100 --count 20 --invalid-pos 0 5 10 15
        """
    )
    
    ap.add_argument("--host", required=True, help="Verifier (RSU) IP address")
    ap.add_argument("--port", type=int, default=5000, help="Verifier port (default 5000)")
    ap.add_argument("--count", type=int, default=10, help="Number of signatures / vehicles (default 10)")
    ap.add_argument("--workers", type=int, default=None, 
                    help="Number of parallel workers (default: min(count, #cores))")
    ap.add_argument("--method", choices=["thread", "process"], default="thread",
                    help="Parallelism method: thread or process (default: thread)")
    ap.add_argument("--message", default="1234567890||TestMessage", 
                    help="Message to sign (format: timestamp||data)")
    ap.add_argument("--runs", type=int, default=1, help="Number of runs (default 1)")
    ap.add_argument("--timeout", type=float, default=30.0, help="Socket timeout (default 30s)")
    ap.add_argument("--no-sync", action="store_true", help="Skip clock synchronization")
    ap.add_argument("--output", help="Save results to JSON file")
    
    # Invalid signature options
    ap.add_argument("--invalid", type=int, default=1, 
                    help="Number of invalid signatures to inject (default 1)")
    ap.add_argument("--invalid-pos", type=int, nargs="+", 
                    help="Specific positions (0-indexed) for invalid signatures")
    
    args = ap.parse_args()
    
    if args.workers is None:
        args.workers = min(args.count, mp.cpu_count())
    
    print(f"\n{'='*70}")
    print(f"SIGNATURE GENERATION WITH INVALID INJECTION")
    print(f"{'='*70}")
    print(f"RSU (verifier): {args.host}:{args.port}")
    print(f"Total signatures per run: {args.count}")
    print(f"Invalid signatures: {args.invalid}")
    if args.invalid_pos:
        print(f"Invalid positions: {args.invalid_pos}")
    else:
        print(f"Invalid positions: Random")
    print(f"Parallel workers: {args.workers}")
    print(f"Method: {args.method}")
    print(f"Runs: {args.runs}")
    print(f"{'='*70}\n")
    
    # Clock synchronization
    if args.no_sync:
        offset_ns = 0
        print("[i] Clock sync disabled (offset_ns=0)\n")
    else:
        try:
            print("[*] Performing clock synchronization...")
            offset_ns = do_clock_sync(args.host, args.port, samples=10, timeout=args.timeout)
            print(f"[✓] Clock offset: {offset_ns} ns ({offset_ns/1e6:.3f} ms)\n")
        except Exception as e:
            print(f"[!] Clock sync failed: {e}")
            print("[!] Using offset_ns=0\n")
            offset_ns = 0
    
    all_results = []
    
    for run_idx in range(1, args.runs + 1):
        print(f"\n{'='*70}")
        print(f"RUN {run_idx}/{args.runs}")
        print(f"{'='*70}")
        
        # 1) Measure ONE real signature generation time (sequential)
        t_sig_start = time.time()
        _ = ARA_Sign_single(args.message)
        t_sig_end = time.time()
        single_sig_ms = (t_sig_end - t_sig_start) * 1000.0
        print(f"[*] One-signature generation time (sequential): {single_sig_ms:.2f} ms")
        
        # 2) Generate signatures with invalid injection
        signatures, gen_time_sec_parallel, invalid_indices = generate_signatures_parallel(
            count=args.count,
            message_str=args.message,
            workers=args.workers,
            method=args.method,
            invalid_count=args.invalid,
            invalid_positions=args.invalid_pos
        )
        
        # 3) Send to verifier and measure network round-trip
        print(f"\n[*] Sending {len(signatures)} signatures to RSU for batch verification...")
        print(f"[!] Expecting verifier to detect {len(invalid_indices)} invalid signature(s)")
        
        payload = {
            "type": "signatures",
            "count": len(signatures),
            "sigma_hex": signatures,
            "t0_ns": time.time_ns(),
        }
        
        try:
            with socket.create_connection((args.host, args.port), timeout=args.timeout) as s:
                t_send = time.time()
                _send_json(s, payload)
                resp = _recv_json(s)
                t_recv = time.time()
                network_time_ms = (t_recv - t_send) * 1000.0
        except Exception as e:
            print(f"[!] Network error: {e}")
            continue
        
        # 4) Check verification result
        verification_ok = resp.get("ok", False)
        part1_all = resp.get("part1_all", False)
        part2_ok = resp.get("part2", False)
        
        print(f"\n[VERIFICATION RESULT]")
        print(f"  Overall: {'✓ PASSED' if verification_ok else '✗ FAILED'}")
        print(f"  Part 1 (Schnorr checks): {'✓ PASSED' if part1_all else '✗ FAILED'}")
        print(f"  Part 2 (Pairing check):  {'✓ PASSED' if part2_ok else '✗ FAILED'}")
        
        # 5) Show which signatures failed
        if not part1_all:
            part1_results = resp.get("part1_results", [])
            failed_indices = [r["index"] for r in part1_results if not r.get("ok", False)]
            print(f"\n  Failed signature indices: {failed_indices}")
            print(f"  Expected invalid indices: {invalid_indices}")
            
            if set(failed_indices) == set(invalid_indices):
                print(f"  ✓ Detection CORRECT: All and only invalid signatures detected!")
            else:
                unexpected = set(failed_indices) - set(invalid_indices)
                missed = set(invalid_indices) - set(failed_indices)
                if unexpected:
                    print(f"  ⚠ Unexpected failures: {unexpected}")
                if missed:
                    print(f"  ⚠ Missed invalid signatures: {missed}")
        
        # 6) Extract timings
        verify_time_part1_sec = resp.get("time_part1_sec", 0.0)
        verify_time_part2_sec = resp.get("time_part2_sec", 0.0)
        verify_time_total_sec = resp.get("total_verify_time_sec", 0.0)
        verification_total_ms = verify_time_total_sec * 1000.0
        
        total_end_to_end_ms = single_sig_ms + network_time_ms
        
        # 7) Print timing breakdown
        print(f"\nTiming Breakdown (per run):")
        print(f"  ONE-signature generation (sequential): {single_sig_ms:.2f} ms")
        print(f"  Network round-trip (batch + verify):  {network_time_ms:.2f} ms")
        print(f"  RSU verification Part 1 (Schnorr):    {verify_time_part1_sec*1000:.2f} ms")
        print(f"  RSU verification Part 2 (Pairing):    {verify_time_part2_sec*1000:.2f} ms")
        print(f"  RSU verification TOTAL:                {verification_total_ms:.2f} ms")
        print(f"  {'─'*50}")
        print(f"  TOTAL END-TO-END TIME:                 {total_end_to_end_ms:.2f} ms")
        
        # 8) Store results
        result = {
            "run": run_idx,
            "signature_count": args.count,
            "invalid_count": len(invalid_indices),
            "invalid_indices": invalid_indices,
            "verification_ok": verification_ok,
            "part1_passed": part1_all,
            "part2_passed": part2_ok,
            "single_signature_generation_ms": single_sig_ms,
            "network_time_ms": network_time_ms,
            "verification_part1_ms": verify_time_part1_sec * 1000.0,
            "verification_part2_ms": verify_time_part2_sec * 1000.0,
            "verification_total_ms": verification_total_ms,
            "total_end_to_end_ms": total_end_to_end_ms,
        }
        all_results.append(result)
    
    # ============================
    # Summary
    # ============================
    if all_results:
        print(f"\n{'='*70}")
        print(f"SUMMARY over {len(all_results)} runs")
        print(f"{'='*70}")
        
        detection_correct = sum(1 for r in all_results if not r["verification_ok"])
        print(f"Runs with invalid signatures detected: {detection_correct}/{len(all_results)}")
        
        avg_single_sig_ms = sum(r["single_signature_generation_ms"] for r in all_results) / len(all_results)
        avg_network_ms = sum(r["network_time_ms"] for r in all_results) / len(all_results)
        avg_verify_total_ms = sum(r["verification_total_ms"] for r in all_results) / len(all_results)
        avg_total_ms = sum(r["total_end_to_end_ms"] for r in all_results) / len(all_results)
        
        print(f"\nAverage ONE-signature generation: {avg_single_sig_ms:.2f} ms")
        print(f"Average RTT (network + verify):   {avg_network_ms:.2f} ms")
        print(f"Average RSU verification TOTAL:   {avg_verify_total_ms:.2f} ms")
        print(f"Average TOTAL END-TO-END time:    {avg_total_ms:.2f} ms")
    
    # ============================
    # Save to file
    # ============================
    if args.output and all_results:
        output_data = {
            "configuration": {
                "host": args.host,
                "port": args.port,
                "signature_count": args.count,
                "invalid_count": args.invalid,
                "invalid_positions": args.invalid_pos,
                "parallel_workers": args.workers,
                "method": args.method,
                "runs": args.runs,
                "message": args.message,
            },
            "results": all_results,
        }
        with open(args.output, 'w') as f:
            json.dump(output_data, f, indent=2)
        print(f"\n[✓] Results saved to: {args.output}")
    
    print(f"\n{'='*70}\n")

if __name__ == "__main__":
    main()