import pytest
from protocols import ConfigError, safe_host, build_config, build_inbound
from models import Node
from security import encrypt_secret


def make_node():
    return Node(
        name="test-node", host="vpn.example.com", proxy_ip=None,
        port_start=20000, port_end=20100,
        agent_url="https://agent.example.com",
        agent_token_encrypted=encrypt_secret("A" * 64),
        tls_sni="vpn.example.com", tls_cert_path="/etc/ssl/fullchain.pem",
        tls_key_path="/etc/ssl/privkey.pem", reality_sni="www.example.com",
        reality_private_key_encrypted=encrypt_secret("test-private-key"),
        reality_public_key="test-public-key", reality_short_id="abcd1234",
        enabled=True,
    )


@pytest.mark.parametrize("host,expected", [
    ("VPN.Example.com", "vpn.example.com"),
    ("203.0.113.5", "203.0.113.5"),
])
def test_safe_host(host, expected):
    assert safe_host(host) == expected


def test_rejects_injection_in_host():
    with pytest.raises(ConfigError):
        safe_host("example.com/path?x=1")


@pytest.mark.parametrize("protocol,transport,security", [
    ("vless", "tcp", "reality"),
    ("vless", "ws", "tls"),
    ("vless", "grpc", "tls"),
    ("vless", "xhttp", "tls"),
    ("vmess", "tcp", "tls"),
    ("trojan", "tcp", "tls"),
    ("shadowsocks", "tcp", "none"),
])
def test_inbound_and_link_are_created(protocol, transport, security):
    node = make_node()
    credential = "00000000-0000-4000-8000-000000000001" if protocol in {"vless", "vmess"} else "test-password"
    data = {"protocol": protocol, "transport": transport, "security": security,
            "sni": "www.example.com" if security == "reality" else "vpn.example.com",
            "path": "/test", "service_name": "grpc-test", "flow": "",
            "cipher": "chacha20-ietf-poly1305"}
    inbound = build_inbound(node, data, credential, "test@rix.local", 20001, "rix-0123456789abcdef01234567")
    link = build_config(node, protocol, transport, security, credential, 20001,
                        "Test user", data["sni"], data["path"], data["service_name"],
                        data["flow"], data["cipher"])
    assert inbound["protocol"] == protocol
    assert inbound["port"] == 20001
    assert link.startswith({"vless":"vless://", "vmess":"vmess://", "trojan":"trojan://", "shadowsocks":"ss://"}[protocol])


def test_reality_rejected_for_trojan():
    node = make_node()
    with pytest.raises(ConfigError):
        build_inbound(node, {"protocol":"trojan", "transport":"tcp", "security":"reality",
                             "sni":"www.example.com", "path":"/", "service_name":"",
                             "flow":"", "cipher":"chacha20-ietf-poly1305"},
                      "password", "test@rix.local", 20001, "rix-0123456789abcdef01234567")


def test_ipv6_link_is_bracketed():
    node = make_node()
    node.host = "2001:db8::1"
    link = build_config(node, "vless", "tcp", "none", "00000000-0000-4000-8000-000000000001", 20001, "IPv6")
    assert "@[2001:db8::1]:20001" in link
