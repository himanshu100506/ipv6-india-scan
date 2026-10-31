import sys

import pandas as pd

if len(sys.argv) != 3:
    print("usage: python compare_runs.py runs/<old_run> runs/<new_run>")
    sys.exit(1)

old_dir, new_dir = sys.argv[1], sys.argv[2]
old = pd.read_csv(f"{old_dir}/results.csv")
new = pd.read_csv(f"{new_dir}/results.csv")
meta = pd.read_csv("domains_in_meta.csv")

m = old.merge(new, on="domain", suffixes=("_old", "_new")).merge(meta, on="domain", how="left")
print(f"hosts in both runs: {len(m)}")

pd.set_option("display.width", 220)
pd.set_option("display.max_columns", 30)
pd.set_option("display.max_colwidth", 40)

changed = m[m["verdict_old"] != m["verdict_new"]]
print(f"verdict changed: {len(changed)} ({round(100 * len(changed) / len(m), 1)}%)\n")

print("=== Transitions (old -> new) ===")
print(changed.groupby(["verdict_old", "verdict_new"]).size()
      .sort_values(ascending=False).to_string())

print("\n=== Changed hosts: what each family did in each run ===")
cols = ["domain", "category", "verdict_old", "verdict_new",
        "v4_stage_failed_old", "v4_error_old", "v4_status_new",
        "v6_stage_failed_old", "v6_error_old", "v6_status_new"]
print(changed[cols].to_string(index=False))

# Do transient failures explain the changes? Old v4 TCP timeouts that now connect:
t4 = m[(m["v4_stage_failed_old"] == "tcp") & (m["v4_error_old"] == "timeout")]
rec4 = t4[t4["v4_status_new"].notna()]
print(f"\nv4 TCP timeouts in old run: {len(t4)}; got an HTTP answer in new run: {len(rec4)}")

t6 = m[(m["v6_stage_failed_old"] == "tcp") & (m["v6_error_old"] == "timeout")]
rec6 = t6[t6["v6_status_new"].notna()]
print(f"v6 TCP timeouts in old run: {len(t6)}; got an HTTP answer in new run: {len(rec6)}")

# Most robust candidates: advertised-but-broken in BOTH runs
persist = m[m["verdict_old"].str.startswith("advertised_but_broken")
            & m["verdict_new"].str.startswith("advertised_but_broken")]
print(f"\n=== Advertised-but-broken in BOTH runs ({len(persist)}) ===")
print(persist[["domain", "category", "host_type", "v6_stage_failed_old",
               "v6_error_old", "v6_stage_failed_new", "v6_error_new"]].to_string(index=False))

changed.to_csv(f"{new_dir}/changed_vs_{old_dir.replace(chr(92), '_').replace('/', '_')}.csv", index=False)
print("\nSaved the changed rows next to the new run's results.")