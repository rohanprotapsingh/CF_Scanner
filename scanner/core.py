import asyncio
from typing import List, Callable, Optional
from .vless_parser import VlessConfig
from .speed_tester import scan_single_ip, scan_single_ip_no_config, ScanResult
from .config import MAX_CONCURRENT_SCANS


class VlessScanner:
    def __init__(self, vless_config: Optional[VlessConfig] = None,
                 max_concurrent: int = MAX_CONCURRENT_SCANS):
        self.config = vless_config
        self.max_concurrent = max_concurrent
        self.results: List[ScanResult] = []
        self.alive_count = 0
        self.scanned_count = 0
        self.total_count = 0
        self.is_scanning = False
        self.progress_callback: Optional[Callable] = None
        self.no_config_mode = False
        self.scan_port = 443
        self.scan_sni = "speed.cloudflare.com"
        self.test_tls = True
        self.test_speed = True

    async def scan_batch(self, ips: List[str],
                         progress_callback: Optional[Callable] = None):
        self.total_count = len(ips)
        self.scanned_count = 0
        self.alive_count = 0
        self.results = []
        self.is_scanning = True
        self.progress_callback = progress_callback
        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def scan_with_sem(ip: str):
            async with semaphore:
                if self.no_config_mode:
                    result = await scan_single_ip_no_config(
                        ip, port=self.scan_port, sni=self.scan_sni,
                        test_tls=self.test_tls, test_speed=self.test_speed,
                    )
                else:
                    result = await scan_single_ip(ip, self.config)
                self.scanned_count += 1
                if result.is_alive:
                    self.alive_count += 1
                if self.progress_callback:
                    self.progress_callback(
                        self.scanned_count, self.total_count,
                        self.alive_count, result
                    )
                return result

        tasks = [scan_with_sem(ip) for ip in ips]
        self.results = await asyncio.gather(*tasks)
        self.is_scanning = False
        return self.results

    def get_alive_results(self) -> List[ScanResult]:
        return [r for r in self.results if r.is_alive]

    def get_top_results(self, count: int = 10, sort_by: str = "score") -> List[ScanResult]:
        alive = self.get_alive_results()
        if sort_by == "ping":
            alive.sort(key=lambda x: x.tcp_ping if x.tcp_ping > 0 else 9999)
        elif sort_by == "speed":
            alive.sort(key=lambda x: x.download_speed, reverse=True)
        else:
            alive.sort(key=lambda x: x.score, reverse=True)
        return alive[:count]
