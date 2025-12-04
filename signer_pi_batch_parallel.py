#!/usr/bin/env python3
# signer_pi_batch_parallel.py
# -----------------------------------------------------
# Parallel signature generation (vehicles) + batch verification at RSU.
# - Simulates N vehicles, each with its own signature.
# - Measures ONE real signature generation time (sequential).
# - Generates N signatures in parallel only to build the RSU batch.
# - Network RTT already includes RSU verification.
# - TOTAL end-to-end time per run:
#       total_end_to_end_ms = single_signature_generation_ms + network_time_ms

import argparse, json, socket, struct, hashlib, sys, time
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
    """Generate a single signature - can be called in parallel"""
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

def worker_sign(idx_and_message):
    """Worker function for parallel signature generation"""
    idx, message = idx_and_message
    return idx, ARA_Sign_single(message)

# ============================
# Parallel signature generation
# ============================

def generate_signatures_parallel(count: int, message_str: str, workers: int = None, method: str = "thread"):
    """
    Generate signatures in parallel, only for building the batch to send to RSU.

    Returns:
        signatures: list of signatures
        gen_time_sec: wall time to generate the WHOLE batch in parallel (info only)
    """
    if workers is None:
        workers = min(count, mp.cpu_count())
    
    print(f"[*] Generating {count} signatures using {workers} {method} workers (for RSU batch)...")
    
    work_items = [(i, message_str) for i in range(count)]
    
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
    print(f"[✓] Batch of {count} signatures generated in {gen_time_sec:.3f}s ({rate:.1f} sigs/sec)")
    
    return signatures, gen_time_sec

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
        description="Parallel Signature Generation (vehicles) + Batch Verification (RSU)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example usage:
  # 10 vehicles, each generating 1 signature (simulated), verified as a batch:
  python3 signer_pi_batch_parallel.py --host 192.168.1.100 --count 10 --workers 10

  # 100 vehicles, limited to 4 worker threads (Pi with 4 cores):
  python3 signer_pi_batch_parallel.py --host 192.168.1.100 --count 100 --workers 4

  # Use process-based parallelism instead of threads:
  python3 signer_pi_batch_parallel.py --host 192.168.1.100 --count 50 --workers 4 --method process
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
    
    args = ap.parse_args()
    
    if args.workers is None:
        args.workers = min(args.count, mp.cpu_count())
    
    print(f"\n{'='*70}")
    print(f"PARALLEL SIGNATURE GENERATION (VEHICLES) + BATCH VERIFICATION (RSU)")
    print(f"{'='*70}")
    print(f"RSU (verifier): {args.host}:{args.port}")
    print(f"Vehicles / signatures per run: {args.count}")
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
        
        # 2) Generate 'count' signatures in parallel (for RSU batch ONLY)
        signatures, gen_time_sec_parallel = generate_signatures_parallel(
            count=args.count,
            message_str=args.message,
            workers=args.workers,
            method=args.method
        )
        
        # 3) Send to verifier and measure network round-trip (includes RSU verification)
        print(f"\n[*] Sending {len(signatures)} signatures to RSU for batch verification...")
        
        payload = {
            "type": "signatures",
            "count": len(signatures),
            "sigma_hex": signatures,
            "t0_ns": time.time_ns(),  # kept for compatibility only
        }
        
        try:
            with socket.create_connection((args.host, args.port), timeout=args.timeout) as s:
                t_send = time.time()
                _send_json(s, payload)
                resp = _recv_json(s)
                t_recv = time.time()
                network_time_ms = (t_recv - t_send) * 1000.0  # RTT = network + RSU verify
        except Exception as e:
            print(f"[!] Network error: {e}")
            continue
        
        if not resp.get("ok", False):
            print(f"[!] Verification failed: {resp.get('error', 'Unknown error')}")
            continue
        
        # 4) Extract RSU verification timings (INFORMATIONAL ONLY)
        verify_time_part1_sec = resp.get("time_part1_sec", 0.0)
        verify_time_part2_sec = resp.get("time_part2_sec", 0.0)
        verify_time_total_sec = resp.get("total_verify_time_sec", 0.0)
        verification_total_ms = verify_time_total_sec * 1000.0
        
        # 5) TOTAL END-TO-END TIME (for ONE vehicle)
        total_end_to_end_ms = single_sig_ms + network_time_ms
        
        # 6) Print breakdown
        print(f"\n[✓] Batch verification SUCCESSFUL")
        print(f"\nTiming Breakdown (per run):")
        print(f"  ONE-signature generation (sequential, per vehicle): {single_sig_ms:.2f} ms")
        print(f"  Network round-trip (batch, incl. RSU verification): {network_time_ms:.2f} ms")
        print(f"  RSU verification Part 1 (Schnorr checks):           {verify_time_part1_sec*1000:.2f} ms")
        print(f"  RSU verification Part 2 (Pairing check):            {verify_time_part2_sec*1000:.2f} ms")
        print(f"  RSU verification TOTAL (informational):             {verification_total_ms:.2f} ms")
        print(f"  {'─'*50}")
        print(f"  TOTAL END-TO-END TIME (ONE vehicle + RSU):          {total_end_to_end_ms:.2f} ms")
        
        # 7) Store results
        result = {
            "run": run_idx,
            "signature_count": args.count,
            "parallel_workers": args.workers,
            "single_signature_generation_ms": single_sig_ms,
            "network_time_ms": network_time_ms,          # includes verification
            "verification_part1_ms": verify_time_part1_sec * 1000.0,
            "verification_part2_ms": verify_time_part2_sec * 1000.0,
            "verification_total_ms": verification_total_ms,
            "total_end_to_end_ms": total_end_to_end_ms,
        }
        all_results.append(result)
    
    # ============================
    # Summary over runs
    # ============================
    if all_results:
        print(f"\n{'='*70}")
        print(f"SUMMARY over {len(all_results)} successful runs")
        print(f"{'='*70}")
        
        avg_single_sig_ms = sum(r["single_signature_generation_ms"] for r in all_results) / len(all_results)
        avg_network_ms = sum(r["network_time_ms"] for r in all_results) / len(all_results)
        avg_verify_total_ms = sum(r["verification_total_ms"] for r in all_results) / len(all_results)
        avg_total_ms = sum(r["total_end_to_end_ms"] for r in all_results) / len(all_results)
        
        print(f"Average ONE-signature generation time: {avg_single_sig_ms:.2f} ms")
        print(f"Average RTT (network + RSU verify):    {avg_network_ms:.2f} ms")
        print(f"Average RSU verification TOTAL (info):  {avg_verify_total_ms:.2f} ms")
        print(f"Average TOTAL END-TO-END time:          {avg_total_ms:.2f} ms")
        
        if len(all_results) > 1:
            import statistics
            std_total = statistics.stdev(r["total_end_to_end_ms"] for r in all_results)
            print(f"Std dev of TOTAL END-TO-END time:      ±{std_total:.2f} ms")
    
    # ============================
    # Save to file
    # ============================
    if args.output and all_results:
        output_data = {
            "configuration": {
                "host": args.host,
                "port": args.port,
                "signature_count": args.count,
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
