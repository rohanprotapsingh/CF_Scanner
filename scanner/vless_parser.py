from urllib.parse import parse_qs, unquote
from dataclasses import dataclass


@dataclass
class VlessConfig:
    protocol: str = "vless"
    uuid: str = ""
    password: str = ""
    address: str = ""
    port: int = 443
    encryption: str = "none"
    flow: str = ""
    security: str = "tls"
    sni: str = ""
    fingerprint: str = ""
    alpn: str = ""
    transport_type: str = "ws"
    path: str = "/"
    host: str = ""
    service_name: str = ""
    pbk: str = ""
    sid: str = ""
    spider_x: str = ""
    remark: str = ""
    original_config: str = ""
    grpc_mode: str = "gun"
    allow_insecure: bool = False

    def is_tls(self) -> bool:
        return self.security in ("tls", "reality")

    def is_reality(self) -> bool:
        return self.security == "reality"

    def is_ws(self) -> bool:
        return self.transport_type == "ws"

    def is_grpc(self) -> bool:
        return self.transport_type == "grpc"

    def is_trojan(self) -> bool:
        return self.protocol == "trojan"

    def is_vless(self) -> bool:
        return self.protocol == "vless"

    def get_effective_port(self) -> int:
        return self.port

    def get_auth(self) -> str:
        if self.protocol == "trojan":
            return self.password
        return self.uuid

    def to_config_url(self, ip: str) -> str:
        if self.protocol == "trojan":
            return self._to_trojan_url(ip)
        return self._to_vless_url(ip)

    def to_vless_url(self, ip: str) -> str:
        return self.to_config_url(ip)

    def _to_vless_url(self, ip: str) -> str:
        params = []
        params.append(f"encryption={self.encryption}")
        params.append(f"security={self.security}")
        params.append(f"type={self.transport_type}")
        if self.sni:
            params.append(f"sni={self.sni}")
        if self.fingerprint:
            params.append(f"fp={self.fingerprint}")
        if self.alpn:
            params.append(f"alpn={self.alpn}")
        if self.flow:
            params.append(f"flow={self.flow}")
        if self.transport_type == "ws":
            if self.path:
                params.append(f"path={self.path}")
            if self.host:
                params.append(f"host={self.host}")
        elif self.transport_type == "grpc":
            if self.service_name:
                params.append(f"serviceName={self.service_name}")
            if self.grpc_mode:
                params.append(f"mode={self.grpc_mode}")
        if self.is_reality():
            if self.pbk:
                params.append(f"pbk={self.pbk}")
            if self.sid:
                params.append(f"sid={self.sid}")
            if self.spider_x:
                params.append(f"spx={self.spider_x}")
        param_str = "&".join(params)
        remark = f"CF-{ip}"
        return f"vless://{self.uuid}@{ip}:{self.port}?{param_str}#{remark}"

    def _to_trojan_url(self, ip: str) -> str:
        params = []
        params.append(f"security={self.security}")
        params.append(f"type={self.transport_type}")
        if self.sni:
            params.append(f"sni={self.sni}")
        if self.fingerprint:
            params.append(f"fp={self.fingerprint}")
        if self.alpn:
            params.append(f"alpn={self.alpn}")
        if self.transport_type == "ws":
            if self.path:
                params.append(f"path={self.path}")
            if self.host:
                params.append(f"host={self.host}")
        elif self.transport_type == "grpc":
            if self.service_name:
                params.append(f"serviceName={self.service_name}")
            if self.grpc_mode:
                params.append(f"mode={self.grpc_mode}")
        if self.allow_insecure:
            params.append("allowInsecure=1")
        param_str = "&".join(params)
        remark = f"CF-{ip}"
        return f"trojan://{self.password}@{ip}:{self.port}?{param_str}#{remark}"


def parse_config_url(url: str) -> VlessConfig:
    url = url.strip()
    if url.startswith("vless://"):
        return parse_vless_url(url)
    elif url.startswith("trojan://"):
        return parse_trojan_url(url)
    else:
        raise ValueError("Only vless:// and trojan:// supported")


def parse_vless_url(url: str) -> VlessConfig:
    config = VlessConfig()
    config.protocol = "vless"
    config.original_config = url

    url_body = url[8:]
    if '#' in url_body:
        url_body, remark = url_body.rsplit('#', 1)
        config.remark = unquote(remark)
    if '@' not in url_body:
        raise ValueError("Invalid URL format")
    uuid_part, rest = url_body.split('@', 1)
    config.uuid = uuid_part

    if '?' in rest:
        address_port, params_str = rest.split('?', 1)
    else:
        address_port = rest
        params_str = ""

    if address_port.startswith('['):
        bracket_end = address_port.index(']')
        config.address = address_port[1:bracket_end]
        port_str = address_port[bracket_end + 2:]
    else:
        parts = address_port.rsplit(':', 1)
        config.address = parts[0]
        port_str = parts[1] if len(parts) > 1 else "443"

    try:
        config.port = int(port_str)
    except ValueError:
        config.port = 443

    if params_str:
        _parse_params(config, params_str)
    if not config.host and config.sni:
        config.host = config.sni
    return config


def parse_trojan_url(url: str) -> VlessConfig:
    config = VlessConfig()
    config.protocol = "trojan"
    config.original_config = url

    url_body = url[9:]
    if '#' in url_body:
        url_body, remark = url_body.rsplit('#', 1)
        config.remark = unquote(remark)
    if '@' not in url_body:
        raise ValueError("Invalid URL format")

    password_part, rest = url_body.split('@', 1)
    config.password = unquote(password_part)

    if '?' in rest:
        address_port, params_str = rest.split('?', 1)
    else:
        address_port = rest
        params_str = ""

    if address_port.startswith('['):
        bracket_end = address_port.index(']')
        config.address = address_port[1:bracket_end]
        port_str = address_port[bracket_end + 2:]
    else:
        parts = address_port.rsplit(':', 1)
        config.address = parts[0]
        port_str = parts[1] if len(parts) > 1 else "443"

    try:
        config.port = int(port_str)
    except ValueError:
        config.port = 443

    if params_str:
        _parse_params(config, params_str)
    if not config.security:
        config.security = "tls"
    if not config.host and config.sni:
        config.host = config.sni
    return config


def _parse_params(config: VlessConfig, params_str: str):
    params = parse_qs(params_str, keep_blank_values=True)
    config.encryption = params.get('encryption', ['none'])[0]
    config.security = params.get('security', ['tls'])[0]
    config.transport_type = params.get('type', ['ws'])[0]
    config.sni = params.get('sni', [''])[0]
    config.fingerprint = params.get('fp', [''])[0]
    config.alpn = params.get('alpn', [''])[0]
    config.flow = params.get('flow', [''])[0]
    config.path = unquote(params.get('path', ['/'])[0])
    config.host = params.get('host', [''])[0]
    config.service_name = params.get('serviceName', [''])[0]
    config.grpc_mode = params.get('mode', ['gun'])[0]
    config.pbk = params.get('pbk', [''])[0]
    config.sid = params.get('sid', [''])[0]
    config.spider_x = unquote(params.get('spx', [''])[0])
    insecure = params.get('allowInsecure', params.get('insecure', ['0']))[0]
    config.allow_insecure = insecure in ('1', 'true', 'yes')
