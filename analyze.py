import math
import sys

import pandas as pd

if len(sys.argv) != 2:
    print("usage: python analyze.py runs/<run_id>")
    sys.exit(1)

run_dir = sys.argv[1]
res = pd.read_csv(f"{run_dir}/results.csv")
meta = pd.read_csv("domains_in_meta.csv")
df = res.merge(meta, on="domain", how="left")
print(f"rows: {len(df)}, unmatched to meta: {df['category'].isna().sum()}\n")

df["org"] = df["domain"].str.replace(r"^www\.", "", regex=True)
df["resolved"] = df["dns_error"].isna()
df["has_aaaa"] = df["resolved"] & (df["n_aaaa"] > 0)
df["v6_ok"] = df["v6_status"].notna()   # answered an HTTP request over v6
df["v4_ok"] = df["v4_status"].notna()
df["live"] = df["v4_ok"] | df["v6_ok"]  # answered over at least one family
df["adv_works"] = df["has_aaaa"] & df["v6_ok"]
df["adv_live"] = df["has_aaaa"] & df["live"]

pd.set_option("display.width", 220)
pd.set_option("display.max_columns", 30)


def pct(a, b):
    return round(100 * a / b, 1) if b else None


def wilson(k, n, z=1.96):
    """Approximate 95% interval in %. Ignores apex/www clustering, so it is optimistic."""
    if n == 0:
        return None
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    m = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return f"{round(100 * (c - m), 1)}-{round(100 * (c + m), 1)}"


def label(name):
    return name if isinstance(name, str) else " / ".join(map(str, name))


def host_table(data, keys):
    rows = []
    for name, g in data.groupby(keys):
        resolved = int(g["resolved"].sum())
        live = int(g["live"].sum())
        adv = int(g["has_aaaa"].sum())
        adv_live = int(g["adv_live"].sum())
        works = int(g["adv_works"].sum())
        rows.append({
            "group": label(name), "hosts": len(g), "resolved": resolved, "live": live,
            "advertise": adv, "adv_%_of_resolved": pct(adv, resolved),
            "adv_%_of_live": pct(adv_live, live),
            "works_v6": works, "works_%_of_adv": pct(works, adv),
            "works_95ci": wilson(works, adv),
        })
    return pd.DataFrame(rows)


print("=== HOST level, by category ===")
print(host_table(df, "category").to_string(index=False))
print("\n=== HOST level, by category and host type ===")
print(host_table(df, ["category", "host_type"]).to_string(index=False))

# ---------- ORGANIZATION level (apex and www collapsed) ----------
orgs = df.groupby(["category", "org"]).agg(
    resolved=("resolved", "max"),
    live=("live", "max"),
    adv=("has_aaaa", "max"),
    adv_live=("adv_live", "max"),
    works=("adv_works", "max"),
).reset_index()

rows = []
for cat, g in orgs.groupby("category"):
    live = int(g["live"].sum())
    adv_live = int(g["adv_live"].sum())
    adv = int(g["adv"].sum())
    works = int(g["works"].sum())
    rows.append({
        "category": cat, "orgs": len(g), "live": live,
        "adv_%_of_live": pct(adv_live, live),
        "advertise": adv, "works_v6": works,
        "works_%_of_adv": pct(works, adv), "works_95ci": wilson(works, adv),
    })
print("\n=== ORGANIZATION level (IPv6 on apex OR www) ===")
print(pd.DataFrame(rows).to_string(index=False))

# ---------- apex vs www disagreement ----------
df["aaaa_i"] = df["has_aaaa"].astype(int)
both = df[df["resolved"]].pivot_table(
    index=["category", "org"], columns="host_type", values="aaaa_i", aggfunc="max"
).dropna()
if {"apex", "www"} <= set(both.columns):
    print("\n=== Orgs where both apex and www resolve: AAAA disagreement ===")
    summary = both.groupby(level="category").apply(
        lambda g: pd.Series({
            "orgs_with_both": len(g),
            "only_www_has_aaaa": int(((g["apex"] == 0) & (g["www"] == 1)).sum()),
            "only_apex_has_aaaa": int(((g["apex"] == 1) & (g["www"] == 0)).sum()),
        })
    )
    print(summary)

# ---------- DNS errors ----------
print("\n=== DNS errors by host type ===")
print(df[df["dns_error"].notna()].groupby(["dns_error", "host_type"]).size())

# ---------- HTTP status over v6 (full list) ----------
v6s = df.loc[df["v6_ok"], "v6_status"].astype(int)
print("\n=== v6 HTTP status codes (all) ===")
print(v6s.value_counts().sort_index())
print(f"v6 answers with status >= 400: {int((v6s >= 400).sum())} of {len(v6s)}")

# ---------- advertisers that did not answer over v6 ----------
bad = df[df["has_aaaa"] & ~df["v6_ok"]]
print(f"\n=== Advertisers with no v6 answer ({len(bad)}) ===")
print(bad[["domain", "category", "host_type", "v6_stage_failed", "v6_error",
           "v4_status", "v4_error"]].to_string(index=False))

# ---------- possible vantage artifacts ----------
v6ok_v4fail = df[df["v6_ok"] & ~df["v4_ok"] & df["v4_stage_failed"].notna()]
print(f"\n=== v6 answered but v4 failed ({len(v6ok_v4fail)}): v4 failure types ===")
print(v6ok_v4fail.groupby(["v4_stage_failed", "v4_error"], dropna=False).size()
      .sort_values(ascending=False))

noaaaa_dead = df[df["resolved"] & ~df["has_aaaa"] & ~df["v4_ok"] & (df["n_a"] > 0)]
print(f"\n=== no AAAA and v4 probe failed: {len(noaaaa_dead)} ===")
print(noaaaa_dead.groupby(["v4_stage_failed", "v4_error"], dropna=False).size()
      .sort_values(ascending=False).head(12))

v4_tcp_to = df[(df["v4_stage_failed"] == "tcp") & (df["v4_error"] == "timeout")]
print(f"\nAll hosts with v4 TCP timeout from this vantage: {len(v4_tcp_to)}")

flag = pd.concat([bad, v6ok_v4fail]).drop_duplicates(subset="domain")
flag.to_csv(f"{run_dir}/flagged_for_manual_check.csv", index=False)
print(f"\nSaved {len(flag)} flagged rows to {run_dir}/flagged_for_manual_check.csv")