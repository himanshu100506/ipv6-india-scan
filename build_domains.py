import csv
import random
import sys

SEED = 2026  # fixed so the same list always gives the same sample

# Suffix -> category. Order matters: first match wins.
CATEGORIES = [
    (".gov.in", "gov"),
    (".nic.in", "gov"),
    (".ac.in", "education"),
    (".edu.in", "education"),
    (".res.in", "education"),
    (".bank.in", "bank_fin"),
    (".fin.in", "bank_fin"),
    (".co.in", "other_in"),
    (".org.in", "other_in"),
    (".net.in", "other_in"),
    (".in", "other_in"),
]


def categorize(domain):
    for suffix, cat in CATEGORIES:
        if domain.endswith(suffix):
            return cat
    return None


def main():
    if len(sys.argv) < 2:
        print("usage: python build_domains.py tranco.csv [sample_per_category]")
        sys.exit(1)
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else 400

    pools = {}  # category -> list of (rank, domain)
    seen = set()
    with open(sys.argv[1], encoding="utf-8") as f:
        for row in csv.reader(f):
            if len(row) < 2 or not row[0].isdigit():
                continue  # skip header or blank lines
            rank, domain = int(row[0]), row[1].strip().lower()
            cat = categorize(domain)
            if cat is None or domain in seen:
                continue
            seen.add(domain)
            pools.setdefault(cat, []).append((rank, domain))

    print("Full pool per category (all .in domains in the list):")
    for cat, items in sorted(pools.items()):
        print(f"  {cat}: {len(items)}")

    rng = random.Random(SEED)
    kept = []
    print(f"\nSample drawn (seed {SEED}, max {limit} per category):")
    for cat, items in sorted(pools.items()):
        chosen = items if len(items) <= limit else rng.sample(items, limit)
        chosen.sort()
        for rank, domain in chosen:
            kept.append((domain, rank, cat))
        print(f"  {cat}: {len(chosen)}")

    # Scan both the bare domain and the www. host, since they are often configured differently.
    with open("domains_in.txt", "w") as ftxt, \
         open("domains_in_meta.csv", "w", newline="", encoding="utf-8") as fmeta:
        w = csv.writer(fmeta)
        w.writerow(["domain", "host_type", "tranco_rank", "category"])
        for domain, rank, cat in kept:
            ftxt.write(domain + "\n")
            w.writerow([domain, "apex", rank, cat])
            if not domain.startswith("www."):
                ftxt.write("www." + domain + "\n")
                w.writerow(["www." + domain, "www", rank, cat])

    print(f"\nWrote domains_in.txt and domains_in_meta.csv ({len(kept)} organizations)")


if __name__ == "__main__":
    main()