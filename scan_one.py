import ipaddress
import json
import socket
import ssl
import sys
import time
from urllib.parse import urlparse

import dns.resolver

TIMEOUT = 8          # tcp + tls stages
HTTP_TIMEOUT = 15    # waiting for the first HTTP response
UA = "Mozilla/5.0 (research scanner; IPv6 readiness study)"

# Literal IPv6 addresses (no DNS needed) used to verify our own v6 connectivity
V6_PROBES = [("2606:4700:4700::1111", 443), ("2001:4860:4860::8888", 443)]

# Public resolvers that do NOT synthesize AAAA records (no DNS64)
PUBLIC_NS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

# Prefixes used by NAT64 translators; AAAA answers inside these are not real IPv6
NAT64_NETS = [ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48")]


def normalize_domain(raw):
    """Accept 'https://www.x.com/path' or 'www.x.com' and return 'www.x.com'."""
    raw = raw.strip().lower()
    if "://" in raw:
        raw = urlparse(raw).netloc
    raw = raw.split("/")[0].split(":")[0]
    return raw


def elapsed_ms(t):
    return round((time.perf_counter() - t) * 1000, 1)


def preflight_v6():
    """True only if this machine can really reach the IPv6 internet."""
    for addr, port in V6_PROBES:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(5)
        try:
            s.connect((addr, port))
            return True
        except OSError:
            continue
        finally:
            s.close()
    return False


def detect_dns64():
    """ipv4only.arpa has no AAAA; if the system resolver returns one, DNS64 is active."""
    try:
        ans = dns.resolver.resolve("ipv4only.arpa", "AAAA", lifetime=5)
        return [r.to_text() for r in ans]
    except Exception:
        return []


def make_resolver():
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = PUBLIC_NS
    r.lifetime = TIMEOUT
    return r


def is_nat64(addr):
    ip = ipaddress.ip_address(addr)
    return any(ip in net for net in NAT64_NETS)


def check_dns(resolver, domain):
    out = {"aaaa": [], "aaaa_synthesized": [], "a": [], "dns_error": None}
    for rtype, key in (("AAAA", "aaaa"), ("A", "a")):
        try:
            answers = resolver.resolve(domain, rtype)
            out[key] = [r.to_text() for r in answers]
        except dns.resolver.NoAnswer:
            pass  # domain exists, just no record of this type
        except dns.resolver.NXDOMAIN:
            out["dns_error"] = "NXDOMAIN"
            break
        except Exception as e:
            out["dns_error"] = type(e).__name__
    real = [a for a in out["aaaa"] if not is_nat64(a)]
    out["aaaa_synthesized"] = [a for a in out["aaaa"] if is_nat64(a)]
    out["aaaa"] = real
    return out


def probe(domain, addr, family):
    """Connect straight to addr, then TLS, then a plain HTTP GET.
    Records where it fails. A bad certificate is logged in cert_error and the
    connection is retried without verification, so reachability and certificate
    validity are measured separately."""
    r = {
        "addr": addr,
        "tcp_ms": None,
        "tls_ms": None,
        "http_ms": None,
        "status": None,
        "stage_failed": None,
        "error": None,
        "cert_error": None,
    }
    sock = None
    stage = "tcp"
    try:
        for verify in (True, False):
            stage = "tcp"
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            t = time.perf_counter()
            sock.connect((addr, 443))
            r["tcp_ms"] = elapsed_ms(t)

            stage = "tls"
            ctx = ssl.create_default_context()
            if not verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            t = time.perf_counter()
            try:
                sock = ctx.wrap_socket(sock, server_hostname=domain)
            except ssl.SSLCertVerificationError as e:
                if not verify:
                    raise
                r["cert_error"] = e.verify_message
                sock.close()
                continue
            r["tls_ms"] = elapsed_ms(t)
            break

        stage = "http"
        sock.settimeout(HTTP_TIMEOUT)
        t = time.perf_counter()
        req = (
            f"GET / HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: {UA}\r\n"
            "Accept: text/html,application/xhtml+xml,*/*;q=0.8\r\n"
            "Accept-Language: en-IN,en;q=0.9\r\n"
            "Connection: close\r\n\r\n"
        )
        sock.sendall(req.encode())
        data = sock.recv(256)
        r["http_ms"] = elapsed_ms(t)
        parts = data.split(b"\r\n", 1)[0].decode("latin-1", "replace").split()
        if len(parts) >= 2 and parts[0].startswith("HTTP/") and parts[1].isdigit():
            r["status"] = int(parts[1])
        else:
            r["stage_failed"] = "http"
            r["error"] = "bad_response"
    except socket.timeout:
        r["stage_failed"], r["error"] = stage, "timeout"
    except ConnectionRefusedError:
        r["stage_failed"], r["error"] = stage, "refused"
    except ssl.SSLError as e:
        r["stage_failed"], r["error"] = stage, f"ssl_error: {str(e)[:60]}"
    except OSError as e:
        r["stage_failed"], r["error"] = stage, f"oserror_{e.errno}"
    finally:
        if sock:
            sock.close()
    return r


def verdict(res):
    d = res["dns"]
    if d["dns_error"]:
        return f"dns_error_{d['dns_error']}"
    if not d["aaaa"]:
        return "no_aaaa"
    v6, v4 = res["v6"], res["v4"]
    if v6 and v6.get("error") == "no_v6_vantage":
        return "aaaa_present_v6_untested"
    v6_ok = bool(v6 and v6["status"] is not None)
    v4_ok = bool(v4 and v4["status"] is not None)
    if v6_ok and v4_ok:
        return "works_v6"
    if v6_ok and not v4_ok:
        return "v6_ok_v4_fail"
    if not v6_ok and v4_ok:
        return f"advertised_but_broken_at_{v6['stage_failed']}"
    return "both_fail_excluded"


def scan(resolver, domain, v6_valid):
    res = {"domain": domain, "dns": check_dns(resolver, domain), "v6": None, "v4": None}
    d = res["dns"]
    if d["a"]:
        res["v4"] = probe(domain, d["a"][0], socket.AF_INET)
    if d["aaaa"]:
        if v6_valid:
            res["v6"] = probe(domain, d["aaaa"][0], socket.AF_INET6)
        else:
            res["v6"] = {"status": None, "stage_failed": "skipped", "error": "no_v6_vantage"}
    res["verdict"] = verdict(res)
    return res


def load_domains(args):
    if not args:
        return ["google.com"]
    if len(args) == 1 and args[0].endswith(".txt"):
        with open(args[0]) as f:
            raw = [line for line in f if line.strip() and not line.startswith("#")]
    else:
        raw = args
    return [normalize_domain(x) for x in raw]


if __name__ == "__main__":
    v6_valid = preflight_v6()
    print(f"IPv6 vantage valid: {v6_valid}")
    if not v6_valid:
        print("WARNING: this network cannot reach IPv6. v6 results will NOT be recorded.")
    dns64 = detect_dns64()
    if dns64:
        print(f"NOTE: DNS64/NAT64 detected on this network ({dns64[0]}). "
              "Synthesized 64:ff9b:: answers are discarded.")
    resolver = make_resolver()
    for dom in load_domains(sys.argv[1:]):
        res = scan(resolver, dom, v6_valid)
        print(f"\n=== {dom} === verdict: {res['verdict']}")
        print(json.dumps(res, indent=2))