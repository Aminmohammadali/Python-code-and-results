#!/usr/bin/env python3
# signer_pi_batch_parallel_gaussian.py
# -----------------------------------------------------
# Parallel signature generation for "vehicles" and batch
# verification at an RSU with GAUSSIAN delay modeling.
#
# NETWORK MODELING:
#   Delay is modeled as a Gaussian random variable with mean μ and 
#   standard deviation σ, truncated at 0 to avoid negative delays.

import argparse
import json
import socket
import struct
import hashlib
import sys
import time
import random
import statistics
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
    return s.replace("<", "").replace(">", "").replace("0x", "").replace(" ", "").strip()

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
    """
    Message format: "timestamp||ID"
    """
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

def sample_gaussian_delay(mu: float, sigma: float) -> float:
    """
    Sample a delay from a Gaussian distribution with mean μ and std σ,
    truncated at 0 to avoid negative delays.
    """
    while True:
        delay = random.gauss(mu, sigma)
        if delay >= 0:
            return delay

# ============================
# Initialize crypto params (for main + workers)
# ============================

def init_worker():
    """Initialize crypto parameters in each worker process/thread."""
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

# Initialize in main process
init_worker()

# ============================
# Signing (single signature)
# ============================

def ARA_Sign_single(message_str: str):
    """Generate a single ARA signature on message_str."""
    g1_, h_, h1_, Y_ = gpk['g1'], gpk['h'], gpk['h1'], gpk['Y']
    A_i_, x_i_, y_i_ = gsk_i['A_i'], gsk_i['x_i'], gsk_i['y_i']

    M = _message_to_bytes(message_str)

    def r():
        return Bn.random(p - 1) + 1

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

    s_k = (r_k + c * k)      % p
    s_x = (r_x + c * x_i_)   % p
    s_d = (r_d + c * delta1) % p
    s_y = (r_y + c * y_i_)   % p

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
    """
    Worker function for parallel signature generation.
    Returns (idx, signature_dict, sig_time_ms)
    """
    idx, message = idx_and_message
    t_start = time.time_ns()
    sig = ARA_Sign_single(message)
    t_end = time.time_ns()
    sig_time_ms = (t_end - t_start) / 1_000_000.0
    return idx, sig, sig_time_ms

# ============================
# Parallel signature generation
# ============================

def generate_signatures_parallel(count: int, message_str: str,
                                 workers: int = None,
                                 method: str = "thread"):
    """
    Generate `count` signatures in parallel.

    Returns:
      signatures: list of signature dicts
      rep_one_sig_ms: representative ONE-sign time (max over per-sig times)
      per_sig_times_ms: list of per-signature generation times
    """
    if workers is None:
        workers = min(count, mp.cpu_count())

    print(f"[*] Generating {count} signatures using {workers} {method} workers...")

    work_items = [(i, message_str) for i in range(count)]

    t_wall_start = time.time()

    if method == "process":
        with ProcessPoolExecutor(max_workers=workers, initializer=init_worker) as executor:
            results = list(executor.map(worker_sign, work_items))
    else:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            results = list(executor.map(worker_sign, work_items))

    t_wall_end = time.time()
    wall_elapsed_ms = (t_wall_end - t_wall_start) * 1000.0

    # Sort by idx
    results.sort(key=lambda x: x[0])
    signatures = [sig for (_, sig, _) in results]
    per_sig_times_ms = [t for (_, _, t) in results]

    rep_one_sig_ms = max(per_sig_times_ms) if per_sig_times_ms else 0.0

    print(f"[✓] Parallel generation wall-clock: {wall_elapsed_ms:.2f} ms "
          f"({count / (wall_elapsed_ms/1000.0):.1f} sigs/sec overall)")
    print(f"    Representative ONE-signature time (max over {count}): "
          f"{rep_one_sig_ms:.2f} ms")

    return signatures, rep_one_sig_ms, per_sig_times_ms

# ============================
# Clock sync (optional)
# ============================

def do_clock_sync(host: str, port: int, samples: int = 10, timeout: float = 5.0) -> int:
    """
    Estimate (verifier_clock - signer_clock) in ns via ping messages.
    """
    offsets = []
    for _ in range(samples):
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
    return offsets[len(offsets) // 2]

# ============================
# Main
# ============================

def main():
    ap = argparse.ArgumentParser(
        description="Parallel vehicles → RSU batch signer with Gaussian delay"
    )

    ap.add_argument("--host", required=True, help="RSU / verifier IP")
    ap.add_argument("--port", type=int, default=5000, help="RSU TCP port (default 5000)")
    ap.add_argument("--message", default="1234567890||TestVehicle",
                    help="Message to sign: 'timestamp||ID' (same for all vehicles)")
    ap.add_argument("--count", type=int, default=10,
                    help="Number of vehicles / signatures per batch (default 10)")
    ap.add_argument("--workers", type=int, default=None,
                    help="Parallel workers (vehicles signing at the same time). "
                         "Default: min(count, CPU cores)")
    ap.add_argument("--method", choices=["thread", "process"], default="thread",
                    help="Parallelism method (default: thread)")
    ap.add_argument("--runs", type=int, default=1,
                    help="Number of batches to send (default 1)")
    ap.add_argument("--timeout", type=float, default=30.0,
                    help="Socket timeout (seconds, default 30)")
    ap.add_argument("--no-sync", action="store_true",
                    help="Skip clock synchronization (only affects measured E2E)")
    ap.add_argument("--model-rtt-ms", type=float,
                    help="If set, use this RTT (ms) as network time per run "
                         "instead of using measured RTT-derived net time or Gaussian delay.")
    ap.add_argument("--output", help="Save per-run results to JSON file")

    # Gaussian delay modeling parameters
    ap.add_argument(
        "--delay-mu", type=float, default=20.0,
        help="Mean (μ) of Gaussian delay distribution in ms (default: 20)"
    )
    ap.add_argument(
        "--delay-sigma", type=float, default=10.0,
        help="Standard deviation (σ) of Gaussian delay distribution in ms (default: 10)"
    )
    ap.add_argument(
        "--per-run-delay", action="store_true",
        help="Sample a new Gaussian delay for EACH run (default: one delay for all runs)"
    )

    args = ap.parse_args()

    if args.workers is None:
        args.workers = min(args.count, mp.cpu_count())

    print("=" * 70)
    print("PARALLEL SIGNING (vehicles) → RSU BATCH VERIFICATION")
    print("WITH GAUSSIAN DELAY MODELING")
    print("=" * 70)
    print(f"RSU address:           {args.host}:{args.port}")
    print(f"Vehicles per batch:    {args.count}")
    print(f"Parallel workers:      {args.workers}")
    print(f"Parallel method:       {args.method}")
    print(f"Runs:                  {args.runs}")
    print(f"Model RTT (ms):        {args.model_rtt_ms if args.model_rtt_ms is not None else 'NONE'}")
    print(f"Gaussian delay μ:      {args.delay_mu} ms")
    print(f"Gaussian delay σ:      {args.delay_sigma} ms")
    print(f"Per-run delay:         {args.per_run_delay}")
    print("=" * 70)
    print()

    # Sample ONE-TIME Gaussian delay if not using per-run delays
    gaussian_delay_once_ms = None
    if not args.per_run_delay:
        gaussian_delay_once_ms = sample_gaussian_delay(args.delay_mu, args.delay_sigma)
        print(f"[i] One-time Gaussian delay for ALL runs: {gaussian_delay_once_ms:.2f} ms "
              f"(μ={args.delay_mu} ms, σ={args.delay_sigma} ms, truncated at 0)")
    else:
        print(f"[i] Gaussian delay will be sampled INDEPENDENTLY for each run "
              f"(μ={args.delay_mu} ms, σ={args.delay_sigma} ms, truncated at 0)")

    # Clock sync for measured E2E info
    if args.no_sync:
        offset_ns = 0
        print("[i] Clock sync DISABLED (offset_ns = 0).")
    else:
        try:
            print("[*] Performing clock synchronization with RSU...")
            offset_ns = do_clock_sync(args.host, args.port, samples=10, timeout=args.timeout)
            print(f"[✓] Clock offset (RSU - vehicle): {offset_ns} ns ({offset_ns/1e6:.3f} ms)")
        except Exception as e:
            print(f"[!] Clock sync failed: {e}")
            print("[!] Proceeding with offset_ns = 0 (measured E2E may be skewed).")
            offset_ns = 0

    all_one_sig_ms = []
    all_rtt_ms = []
    all_verify_ms = []
    all_net_model_ms = []
    all_total_model_ms = []
    all_gaussian_delays = []

    for run_idx in range(1, args.runs + 1):
        print(f"\n--- RUN {run_idx}/{args.runs} ---")

        # Start time for measured E2E
        t_start_ns = time.time_ns()

        # 1) Parallel signature generation
        signatures, one_sig_ms, _per_sig_times = generate_signatures_parallel(
            count=args.count,
            message_str=args.message,
            workers=args.workers,
            method=args.method
        )

        # 2) Send batch to RSU and measure RTT
        payload = {
            "type": "signatures",
            "count": len(signatures),
            "sigma_hex": signatures,
            "t0_ns": t_start_ns,
        }

        try:
            with socket.create_connection((args.host, args.port), timeout=args.timeout) as s:
                t_send = time.time()
                _send_json(s, payload)
                resp = _recv_json(s)
                t_recv = time.time()
        except Exception as e:
            print(f"[!] Network / RSU error: {e}")
            continue

        rtt_ms = (t_recv - t_send) * 1000.0

        if not resp.get("ok", False):
            print(f"[!] RSU verification reported failure: {resp.get('error', 'Unknown error')}")
            continue

        verify_total_ms = float(resp.get("total_verify_time_sec", 0.0)) * 1000.0

        # Approximate measured network-only time
        net_measured_ms = max(rtt_ms - verify_total_ms, 0.0)

        # Measured E2E via clock sync (signer clock)
        verifier_end_ns = int(resp.get("verifier_end_ns", 0))
        verifier_end_on_signer_clock_ns = verifier_end_ns - offset_ns
        measured_e2e_ms = (verifier_end_on_signer_clock_ns - t_start_ns) / 1_000_000.0

        # Choose network model for this run
        if args.model_rtt_ms is not None:
            net_model_ms = float(args.model_rtt_ms)
            net_model_source = "--model-rtt-ms"
            gaussian_delay_this_run = None
        else:
            # Use Gaussian delay
            if args.per_run_delay:
                gaussian_delay_this_run = sample_gaussian_delay(args.delay_mu, args.delay_sigma)
                net_model_ms = gaussian_delay_this_run
                net_model_source = "per-run Gaussian"
            else:
                gaussian_delay_this_run = gaussian_delay_once_ms
                net_model_ms = gaussian_delay_once_ms
                net_model_source = "one-time Gaussian"

        # Final modeled total: signing + network_model + verify
        total_model_ms = one_sig_ms + net_model_ms + verify_total_ms

        print(f"  ONE-signature generation (rep): {one_sig_ms:.2f} ms")
        print(f"  Measured RTT (net + verify):    {rtt_ms:.2f} ms")
        print(f"  RSU verification TOTAL:         {verify_total_ms:.2f} ms")
        print(f"  Measured NET (approx):          {net_measured_ms:.2f} ms")
        print(f"  NET used in model ({net_model_source}): {net_model_ms:.2f} ms")
        print(f"  TOTAL END-TO-END (model):       {total_model_ms:.2f} ms")
        print(f"  Measured E2E via clock sync:    {measured_e2e_ms:.2f} ms")

        all_one_sig_ms.append(one_sig_ms)
        all_rtt_ms.append(rtt_ms)
        all_verify_ms.append(verify_total_ms)
        all_net_model_ms.append(net_model_ms)
        all_total_model_ms.append(total_model_ms)
        all_gaussian_delays.append(gaussian_delay_this_run if gaussian_delay_this_run is not None else net_model_ms)

    # ============================
    # Summary
    # ============================

    if not all_total_model_ms:
        print("\n[!] No successful runs to summarize.")
        return

    def avg(lst):
        return sum(lst) / len(lst)

    print("\n" + "=" * 70)
    print(f"SUMMARY over {len(all_total_model_ms)} successful runs")
    print("=" * 70)

    avg_one_sig   = avg(all_one_sig_ms)
    avg_rtt       = avg(all_rtt_ms)
    avg_verify    = avg(all_verify_ms)
    avg_net_mod   = avg(all_net_model_ms)
    avg_total_mod = avg(all_total_model_ms)

    print(f"Average ONE-signature generation: {avg_one_sig:.2f} ms")
    print(f"Average measured RTT:             {avg_rtt:.2f} ms")
    print(f"Average RSU verification TOTAL:   {avg_verify:.2f} ms")
    print(f"Average NET used in model:        {avg_net_mod:.2f} ms")
    print(f"Average TOTAL END-TO-END (model): {avg_total_mod:.2f} ms")

    if len(all_total_model_ms) > 1:
        std_total = statistics.stdev(all_total_model_ms)
        std_net = statistics.stdev(all_net_model_ms)
        print(f"Std dev of NET (model):              ±{std_net:.2f} ms")
        print(f"Std dev of TOTAL END-TO-END (model): ±{std_total:.2f} ms")

    if args.output:
        results = []
        for i, (sig_ms, rtt, v_ms, net_m, tot_ms, gauss_d) in enumerate(
            zip(all_one_sig_ms, all_rtt_ms, all_verify_ms, all_net_model_ms, 
                all_total_model_ms, all_gaussian_delays),
            start=1
        ):
            results.append({
                "run": i,
                "one_signature_ms": sig_ms,
                "rtt_ms": rtt,
                "verify_total_ms": v_ms,
                "net_model_ms": net_m,
                "gaussian_delay_ms": gauss_d,
                "total_model_ms": tot_ms,
            })

        output_data = {
            "configuration": {
                "host": args.host,
                "port": args.port,
                "count": args.count,
                "workers": args.workers,
                "method": args.method,
                "runs": args.runs,
                "message": args.message,
                "model_rtt_ms": args.model_rtt_ms,
                "delay_mu": args.delay_mu,
                "delay_sigma": args.delay_sigma,
                "per_run_delay": args.per_run_delay,
                "gaussian_delay_once_ms": gaussian_delay_once_ms,
            },
            "results": results,
            "summary": {
                "avg_one_signature_ms": avg_one_sig,
                "avg_rtt_ms": avg_rtt,
                "avg_verify_total_ms": avg_verify,
                "avg_net_model_ms": avg_net_mod,
                "avg_total_model_ms": avg_total_mod,
            }
        }

        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=2)
        print(f"\n[✓] Results saved to: {args.output}")

    print("\nDone.\n")

if __name__ == "__main__":
    main()