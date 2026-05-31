import random
import ipaddress
import requests
from typing import List, Optional
from .config import MAX_IPS_TO_SCAN, OPERATORS

CF_IP_RANGES_V4 = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
]


def fetch_cf_ranges() -> List[str]:
    try:
        resp = requests.get("https://www.cloudflare.com/ips-v4/#", timeout=5)
        if resp.status_code == 200:
            ranges = [line.strip() for line in resp.text.strip().split("\n") if line.strip()]
            if ranges:
                return ranges
    except Exception:
        pass
    return CF_IP_RANGES_V4


def generate_random_ips(
    count: int = MAX_IPS_TO_SCAN,
    custom_ranges: List[str] = None,
    operator: str = "all"
) -> List[str]:
    if custom_ranges and len(custom_ranges) > 0:
        ranges = custom_ranges
    elif operator and operator != "all" and operator in OPERATORS:
        op_ranges = OPERATORS[operator]["ranges"]
        if op_ranges:
            ranges = op_ranges
        else:
            ranges = fetch_cf_ranges()
    else:
        ranges = fetch_cf_ranges()

    all_networks = []
    for cidr in ranges:
        try:
            network = ipaddress.IPv4Network(cidr, strict=False)
            all_networks.append(network)
        except ValueError:
            continue

    if not all_networks:
        raise ValueError("No valid IP range found")

    weights = [n.num_addresses for n in all_networks]
    total_weight = sum(weights)
    weighted = [(net, w / total_weight) for net, w in zip(all_networks, weights)]

    ips = set()
    max_attempts = count * 15
    for _ in range(max_attempts):
        if len(ips) >= count:
            break
        rand = random.random()
        cumulative = 0
        selected_network = all_networks[0]
        for net, weight in weighted:
            cumulative += weight
            if rand <= cumulative:
                selected_network = net
                break
        network_int = int(selected_network.network_address)
        broadcast_int = int(selected_network.broadcast_address)
        if broadcast_int - network_int <= 1:
            continue
        random_ip_int = random.randint(network_int + 1, broadcast_int - 1)
        ip = str(ipaddress.IPv4Address(random_ip_int))
        ips.add(ip)
    return list(ips)


def parse_custom_ranges(text: str) -> List[str]:
    ranges = []
    if not text or not text.strip():
        return ranges
    for line in text.strip().split('\n'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        for part in line.split(','):
            part = part.strip()
            if not part:
                continue
            try:
                ipaddress.IPv4Network(part, strict=False)
                ranges.append(part)
            except ValueError:
                try:
                    ipaddress.IPv4Address(part)
                    ranges.append(part + "/32")
                except ValueError:
                    continue
    return ranges
