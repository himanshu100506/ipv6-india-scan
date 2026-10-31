# IPv6 Readiness of Indian Websites

**Question:** How ready is Indian web infrastructure for IPv6, and where does it break?

## Daily log
- 2026-10-31: repo created and cloned, venv set up, dependencies installed (dnspython, httpx)

## Reading table
| Paper/source | What they measured | Region | Sites or users | Year | Advertised vs works? | Sector/host breakdown? |
|---|---|---|---|---|---|---|

## Method decisions
- Own network IPv6 status: (fill in after test-ipv6.com)
- Timeout: 8s
- User-Agent: research scanner
- Ports checked: 443 only

## Weird results

- Own network (laptop, Airtel broadband): no IPv6 (test-ipv6.com 0/10, 2026-10-31). IPv6 reachability results NOT valid from this network.

- iitd.ac.in: browser shows valid certificate (connection secure), Python reports "unable to get local issuer certificate" on both v4 and v6. Likely incomplete chain sent by server (browser fetches intermediate itself); cause unconfirmed. Not an IPv6 issue.

- iitb.ac.in: IPv4 TLS reset on Jio hotspot (scanner + curl, oserror_10054 / 000); curl returns 200 on Airtel broadband and browser loads on both. Vantage-point effect, cause unconfirmed (site-side Jio blocking vs Jio NAT64/CGNAT path).

- Pools (Tranco <ID>, 2026-10-31): education 1012, gov 1189, other_in 8742. bank_fin empty.
- Pilot: random 500/category, seed 2026. Full run: <decide after pilot>.

- Pilot run 20261031T084241Z: adv% by category (hosts, of resolved): edu 24.0, gov 5.4, other_in 42.2. Works over v6 among advertisers: edu 98.7, gov 76.0 (38/50), other_in 96.3
- Gov apex: 10 advertise, 2 answer over v6; gov www: 40 advertise, 36 answer. Candidate finding, NOT verified (single vantage)
- 138 hosts with v4 TCP timeout from Jio (48 of them answer over v6): likely vantage artifact, checking with broadband curl
- Client limits: UNSAFE_LEGACY_RENEGOTIATION (23 no_aaaa hosts), handshake failures; fix before full run
- Do not report pooled adoption across categories (unequal sampling fractions)


- 8 sampled gov/other_in hosts (ecourts, meity, icmr, dgma, mpwcdmis, mpeoffice, praction, sentrynet): curl -4 answers, curl -6 times out (15s) on JIO. Reproduces scanner result. Cause unresolved (host vs Jio path). Next: second v6 vantage.

- Unit of analysis: organization = apex+www; host-level also reported. Gov adoption 5.9% (host, of live) vs 9.8% (org).
- Pilot org-level: edu 124/126 advertisers answer over v6, gov 37/46, other_in 235/244. 72/661 v6 answers are HTTP >=400.
- 36 gov and 70 other_in orgs have AAAA on www only. Hypothesis (CDN on www), unchecked.
- Gov failures cluster (mp* hosts); two are TCP refused (www.ap.gov.in, mpigr.gov.in).

- Jio curl cross-check (8 hosts): curl -4 answers, curl -6 times out; reproduces scanner. Cause unresolved (host vs Jio path); need 2nd IPv6 vantage.
- scanner v5: relaxed-TLS fallback (legacy renegotiation, small DH, old TLS) recorded in tls_relaxed; pilot run 20261031T084241Z was v4, not comparable


- v5 test (Jio): mpigr.gov.in v4 now 200 with tls_relaxed (pilot v4 undercounted live hosts); v6 TCP refused, same as pilot. mystar.in, cmrcet.ac.in still fail TLS on both families (not legacy-TLS; cause unconfirmed).
- Plan: rerun full list on v5 from Jio, compare with v4 pilot, then second v6 vantage.


- mystar.in, cmrcet.ac.in: TLS handshake fails on v4 and v6 in Python and curl (schannel), also with second A record for cmrcet. Server-side TLS failure likely; browser/broadband check: <fill in>. Excluded from live denominator.

- Full v5 rerun (Jio, same list, 3000 hosts): no_aaaa 2185, works_v6 627, v6_ok_v4_fail 36, broken 18 (tcp 17, http 1), both_fail 11, dns errors 123
- v4 -> v5 changed v6_ok_v4_fail 48 -> 36 although all 48 were v4 TCP timeouts (pre-TLS): suggests transient v4 failures from Jio, not TLS. Compare per host.
- Plan: compare_runs.py, third run at a different time, then second v6 vantage

- v5 rerun vs v4 pilot: org adoption of live stable (edu 25.6, gov 9.9, other_in 51.6); v6 answers 661 -> 663; 28 of 30 advertiser-no-answer hosts identical
- v6_ok_v4_fail 48 -> 36 driven by v4 TCP timeouts from Jio (not TLS): v4 side is noisy, use v6 answers as the measure
- v5 TLS tolerance raised gov live orgs 438 -> 453, adoption share unchanged
- Gov failures persist across both runs but same vantage; need second provider