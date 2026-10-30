import csv
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import scan_one as s

WORKERS = 20

PROBE_KEYS = ("addr", "tcp_ms", "tls_ms", "http_ms", "status", "stage_failed", "error", "cert_error")

FIELDS = [
    "run_id", "scanned_at_utc", "domain", "verdict",
    "n_aaaa", "n_aaaa_synth", "n_a", "dns_error",
] + [f"{fam}_{k}" for fam in ("v6", "v4") for k in PROBE_KEYS]


def scan_safe(domain, v6_valid):
    """One bad domain must never kill the whole run."""
    try:
        return s.scan(s.make_resolver(), domain, v6_valid)
    except Exception as e:
        return {
            "domain": domain,
            "dns": {"aaaa": [], "aaaa_synthesized": [], "a": [], "dns_error": None},
            "v6": None,
            "v4": None,
            "verdict": "scanner_error",
            "error": type(e).__name__,
        }


def flatten(res, run_id, ts):
    d = res["dns"]
    row = {
        "run_id": run_id,
        "scanned_at_utc": ts,
        "domain": res["domain"],
        "verdict": res["verdict"],
        "n_aaaa": len(d["aaaa"]),
        "n_aaaa_synth": len(d["aaaa_synthesized"]),
        "n_a": len(d["a"]),
        "dns_error": d["dns_error"],
    }
    for fam in ("v6", "v4"):
        p = res.get(fam) or {}
        for k in PROBE_KEYS:
            row[f"{fam}_{k}"] = p.get(k)
    return row


def main():
    if len(sys.argv) != 2:
        print("usage: python scan_batch.py domains.txt")
        sys.exit(1)

    domains = list(dict.fromkeys(s.load_domains(sys.argv[1:])))  # dedupe, keep order
    v6_valid = s.preflight_v6()
    dns64 = s.detect_dns64()
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = os.path.join("runs", run_id)
    os.makedirs(out_dir)

    meta = {
        "run_id": run_id,
        "domain_file": sys.argv[1],
        "n_domains": len(domains),
        "v6_vantage_valid": v6_valid,
        "dns64_detected": bool(dns64),
        "resolvers": s.PUBLIC_NS,
        "timeout_s": s.TIMEOUT,
        "http_timeout_s": s.HTTP_TIMEOUT,
        "workers": WORKERS,
        "user_agent": s.UA,
    }
    with open(os.path.join(out_dir, "meta.json"), "w") as f:
        json.dump(meta, f, indent=2)

    print(f"Run {run_id}: {len(domains)} domains, IPv6 vantage valid: {v6_valid}")
    if not v6_valid:
        print("WARNING: no IPv6 on this network. v6 results will be 'aaaa_present_v6_untested'.")

    counts = {}
    done = 0
    with open(os.path.join(out_dir, "results.csv"), "w", newline="", encoding="utf-8") as fcsv, \
         open(os.path.join(out_dir, "raw.jsonl"), "w", encoding="utf-8") as fraw, \
         ThreadPoolExecutor(max_workers=WORKERS) as pool:
        writer = csv.DictWriter(fcsv, fieldnames=FIELDS)
        writer.writeheader()
        futures = [pool.submit(scan_safe, d, v6_valid) for d in domains]
        for fut in as_completed(futures):
            res = fut.result()
            ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
            writer.writerow(flatten(res, run_id, ts))
            fraw.write(json.dumps({"scanned_at_utc": ts, **res}) + "\n")
            fcsv.flush()
            fraw.flush()
            counts[res["verdict"]] = counts.get(res["verdict"], 0) + 1
            done += 1
            if done % 25 == 0 or done == len(domains):
                print(f"{done}/{len(domains)} done")

    print("\nVerdict counts:")
    for k, v in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"  {k}: {v}")
    print(f"\nSaved to {out_dir}/ (results.csv, raw.jsonl, meta.json)")


if __name__ == "__main__":
    main()