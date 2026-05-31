import ssl
import time
import asyncio
import aiohttp
from dataclasses import dataclass
from typing import Tuple
from .vless_parser import VlessConfig
from .config import CONNECT_TIMEOUT, READ_TIMEOUT, SPEED_TEST_TIMEOUT

TLS_PORTS = {443, 2053, 2083, 2087, 2096, 8443}
HTTP_PORTS = {80, 8080, 8880, 2052, 2082, 2086, 2095}


@dataclass
class ScanResult:
    ip: str
    port: int
    is_alive: bool = False
    tcp_ping: float = 0.0
    http_status: int = 0
    tls_handshake_time: float = 0.0
    download_speed: float = 0.0
    total_latency: float = 0.0
    error: str = ""
    score: float = 0.0
    vless_url: str = ""

    def calculate_score(self):
        if not self.is_alive:
            self.score = 0
            return
        ping_score = max(0, 50 - (self.tcp_ping / 20)) if self.tcp_ping > 0 else 0
        speed_score = min(50, self.download_speed / 20)
        self.score = round(ping_score + speed_score, 2)

    def to_dict(self):
        return {
            "ip": self.ip,
            "port": self.port,
            "is_alive": self.is_alive,
            "tcp_ping": self.tcp_ping,
            "http_status": self.http_status,
            "tls_handshake_time": self.tls_handshake_time,
            "download_speed": self.download_speed,
            "total_latency": self.total_latency,
            "score": round(self.score, 2),
            "vless_url": self.vless_url,
            "error": self.error,
        }


def is_tls_port(port: int) -> bool:
    return port in TLS_PORTS


def _make_ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def tcp_ping(ip: str, port: int, timeout: float = CONNECT_TIMEOUT) -> Tuple[bool, float]:
    try:
        start = time.monotonic()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        elapsed = (time.monotonic() - start) * 1000
        writer.close()
        await writer.wait_closed()
        return True, elapsed
    except Exception:
        return False, 0


async def test_ws_handshake(
    ip: str, port: int, host: str, path: str = "/",
    use_tls: bool = True, timeout: float = CONNECT_TIMEOUT,
) -> Tuple[bool, float]:
    scheme = "https" if use_tls else "http"
    url = f"{scheme}://{ip}:{port}{path}"
    ssl_ctx = _make_ssl_ctx() if use_tls else None
    connector = aiohttp.TCPConnector(ssl=ssl_ctx, force_close=True)
    headers = {
        "Host": host,
        "User-Agent": "Go-http-client/1.1",
        "Connection": "Upgrade",
        "Upgrade": "websocket",
        "Sec-WebSocket-Version": "13",
        "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
    }
    try:
        start = time.monotonic()
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(
                url, headers=headers,
                timeout=aiohttp.ClientTimeout(total=timeout),
                allow_redirects=False,
            ) as resp:
                elapsed = (time.monotonic() - start) * 1000
                if resp.status in (101, 200, 301, 302):
                    return True, elapsed
                return False, elapsed
    except Exception:
        return False, 0
    finally:
        await connector.close()


async def test_grpc_handshake(
    ip: str, port: int, host: str, service_name: str = "",
    use_tls: bool = True, timeout: float = CONNECT_TIMEOUT,
) -> Tuple[bool, float]:
    scheme = "https" if use_tls else "http"
    path = f"/{service_name}/Tun" if service_name else "/Tun"
    url = f"{scheme}://{ip}:{port}{path}"
    ssl_ctx = _make_ssl_ctx() if use_tls else None
    connector = aiohttp.TCPConnector(ssl=ssl_ctx, force_close=True)
    headers = {
        "Host": host,
        "Content-Type": "application/grpc",
        "User-Agent": "grpc-go/1.56.0",
        "TE": "trailers",
    }
    try:
        start = time.monotonic()
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.post(
                url, headers=headers,
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as resp:
                elapsed = (time.monotonic() - start) * 1000
                if resp.status in (200, 204, 400, 405):
                    return True, elapsed
                return False, elapsed
    except Exception:
        return False, 0
    finally:
        await connector.close()


async def test_http_host(
    ip: str, port: int, host: str,
    use_tls: bool = True, timeout: float = READ_TIMEOUT,
) -> Tuple[int, float]:
    scheme = "https" if use_tls else "http"
    url = f"{scheme}://{ip}:{port}/"
    ssl_ctx = _make_ssl_ctx() if use_tls else None
    connector = aiohttp.TCPConnector(ssl=ssl_ctx, force_close=True)
    headers = {
        "Host": host,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    }
    try:
        start = time.monotonic()
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(
                url, headers=headers,
                timeout=aiohttp.ClientTimeout(total=timeout),
                allow_redirects=False,
            ) as resp:
                elapsed = (time.monotonic() - start) * 1000
                return resp.status, elapsed
    except Exception:
        return 0, 0
    finally:
        await connector.close()


async def download_speed_test(
    ip: str, port: int, host: str = "speed.cloudflare.com",
    use_tls: bool = True, timeout: float = SPEED_TEST_TIMEOUT,
    test_bytes: int = 500000,
) -> float:
    scheme = "https" if use_tls else "http"
    ssl_ctx = _make_ssl_ctx() if use_tls else None
    connector = aiohttp.TCPConnector(ssl=ssl_ctx, force_close=True)
    try:
        start = time.monotonic()
        total_bytes = 0
        async with aiohttp.ClientSession(connector=connector) as session:
            url = f"{scheme}://{ip}:{port}/__down?bytes={test_bytes}"
            headers = {"Host": "speed.cloudflare.com", "User-Agent": "Mozilla/5.0"}
            try:
                async with session.get(
                    url, headers=headers,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                ) as resp:
                    if resp.status == 200:
                        async for chunk in resp.content.iter_chunked(16384):
                            total_bytes += len(chunk)
                            if time.monotonic() - start > timeout:
                                break
            except Exception:
                try:
                    url2 = f"{scheme}://{ip}:{port}/generate_204"
                    headers2 = {"Host": host, "User-Agent": "Mozilla/5.0"}
                    async with session.get(
                        url2, headers=headers2,
                        timeout=aiohttp.ClientTimeout(total=timeout),
                    ) as resp:
                        async for chunk in resp.content.iter_chunked(8192):
                            total_bytes += len(chunk)
                except Exception:
                    pass
        elapsed = time.monotonic() - start
        if elapsed > 0 and total_bytes > 0:
            return (total_bytes / 1024) / elapsed
        return 0
    except Exception:
        return 0
    finally:
        await connector.close()


async def scan_single_ip(ip: str, vless_config: VlessConfig) -> ScanResult:
    port = vless_config.get_effective_port()
    result = ScanResult(ip=ip, port=port)

    if vless_config.security == "none":
        use_tls = is_tls_port(port)
    else:
        use_tls = vless_config.is_tls()

    host = vless_config.host or vless_config.sni or ""

    try:
        alive, ping = await tcp_ping(ip, port)
        if not alive:
            result.error = "TCP Failed"
            return result

        transport = vless_config.transport_type

        if transport == "ws":
            path = vless_config.path or "/"
            if not path.startswith('/'):
                path = '/' + path
            ws_ok, ws_time = await test_ws_handshake(ip, port, host, path, use_tls)
            if not ws_ok:
                result.error = "WS Failed"
                return result
            result.is_alive = True
            result.tcp_ping = round(ws_time, 2)

        elif transport == "grpc":
            grpc_ok, grpc_time = await test_grpc_handshake(
                ip, port, host, vless_config.service_name, use_tls
            )
            if not grpc_ok:
                result.error = "gRPC Failed"
                return result
            result.is_alive = True
            result.tcp_ping = round(grpc_time, 2)

        elif transport in ("tcp", "http"):
            http_status, http_time = await test_http_host(ip, port, host, use_tls)
            if http_status == 0:
                result.error = "HTTP Failed"
                return result
            result.is_alive = True
            result.tcp_ping = round(http_time, 2)
            result.http_status = http_status

        else:
            result.is_alive = True
            result.tcp_ping = round(ping, 2)

        if result.is_alive:
            speed = await download_speed_test(ip, port, host, use_tls)
            result.download_speed = round(speed, 2)

        result.vless_url = vless_config.to_config_url(ip)
        result.calculate_score()

    except Exception as e:
        result.error = str(e)
    return result


async def scan_single_ip_no_config(
    ip: str, port: int = 443, sni: str = "speed.cloudflare.com",
    test_tls: bool = True, test_speed: bool = True,
) -> ScanResult:
    result = ScanResult(ip=ip, port=port)
    use_tls = is_tls_port(port)
    try:
        alive, ping = await tcp_ping(ip, port)
        if not alive:
            result.error = "TCP Failed"
            return result
        result.tcp_ping = round(ping, 2)

        http_status, http_time = await test_http_host(ip, port, sni, use_tls)
        if http_status == 0:
            result.error = "HTTP Failed"
            return result
        result.is_alive = True
        result.http_status = http_status
        result.total_latency = round(http_time, 2)

        if test_speed:
            speed = await download_speed_test(ip, port, sni, use_tls)
            result.download_speed = round(speed, 2)

        result.calculate_score()
    except Exception as e:
        result.error = str(e)
    return result
