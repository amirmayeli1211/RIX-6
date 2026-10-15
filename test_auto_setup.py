from pathlib import Path

import main
from railway_xray import INTERNAL_PORTS, SUPPORTED_PROTOCOLS, WEBSOCKET_PATHS, RailwayXray


def test_all_visible_jinja_templates_compile():
    for name in ("base.html", "clients.html", "dashboard.html", "login.html", "subscription.html"):
        main.templates.env.get_template(name)


def test_dashboard_has_server_information_and_no_node_workflow():
    dashboard = Path("dashboard.html").read_text(encoding="utf-8")
    base = Path("base.html").read_text(encoding="utf-8")
    assert "اطلاعات سرور" in dashboard
    assert "Railway · یک سرویس" in dashboard
    assert "افزودن سرور" not in base
    assert 'href="/nodes"' not in base


def test_railway_protocols_are_limited_to_http_websocket_compatible_options():
    assert set(SUPPORTED_PROTOCOLS) == {"vless", "vmess", "trojan"}
    assert set(INTERNAL_PORTS) == set(SUPPORTED_PROTOCOLS)
    assert set(WEBSOCKET_PATHS) == set(SUPPORTED_PROTOCOLS)
    assert all(path.startswith("/rws/") for path in WEBSOCKET_PATHS.values())


def test_generated_xray_config_uses_loopback_ws_inbounds():
    config = RailwayXray().build_config([])
    inbounds = {entry["protocol"]: entry for entry in config["inbounds"]}
    assert set(inbounds) == {"vless", "vmess", "trojan"}
    for protocol, inbound in inbounds.items():
        assert inbound["listen"] == "127.0.0.1"
        assert inbound["port"] == INTERNAL_PORTS[protocol]
        assert inbound["streamSettings"]["network"] == "ws"
        assert inbound["streamSettings"]["wsSettings"]["path"] == WEBSOCKET_PATHS[protocol]


def test_obsolete_vps_installer_and_agent_routes_are_absent():
    paths = {route.path for route in main.app.routes}
    assert "/install-node.sh" not in paths
    assert "/xray-agent.py" not in paths
    assert "/nodes/create" not in paths
    assert "/clients/create" in paths


def test_dockerfile_uses_a_pinned_stable_xray_release():
    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")
    assert "APP_ENV=production" in dockerfile
    assert "v26.3.27" in dockerfile
    assert "v26.9.30" not in dockerfile
    assert "sha256sum -c -" in dockerfile


def test_health_endpoint_does_not_require_login():
    from fastapi.testclient import TestClient

    with TestClient(main.app) as client:
        response = client.get("/health")
    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["service"] == "rix-storm-panel"


def test_admin_can_create_user_without_manual_node_setup(tmp_path, monkeypatch):
    import re
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    import database
    from models import Admin, Client
    from security import password_hash, decrypt_secret

    test_engine = create_engine(
        f"sqlite:///{tmp_path / 'panel-test.sqlite3'}",
        connect_args={"check_same_thread": False},
    )
    TestSessionLocal = sessionmaker(bind=test_engine, autoflush=False, autocommit=False, expire_on_commit=False)
    monkeypatch.setattr(database, "engine", test_engine)
    monkeypatch.setattr(database, "SessionLocal", TestSessionLocal)
    monkeypatch.setattr(main, "SessionLocal", TestSessionLocal)
    monkeypatch.setattr(main, "PUBLIC_BASE_URL", "https://sample.up.railway.app")
    monkeypatch.setattr(main.runtime, "start_empty", lambda: None)
    monkeypatch.setattr(main.runtime, "shutdown", lambda: None)
    monkeypatch.setattr(main.runtime, "sync", lambda db, node_id: {"state": "online", "configured_users": 1})
    database.init_db()
    with TestSessionLocal() as db:
        db.add(Admin(username="test-admin", password_hash=password_hash("Test-Only-Password-2026!"), active=True))
        db.commit()

    try:
        with TestClient(main.app, base_url="https://testserver") as client:
            login_page = client.get("/login")
            csrf = re.search(r'name="csrf" value="([^\"]+)"', login_page.text).group(1)
            login = client.post("/login", data={
                "csrf": csrf, "username": "test-admin", "password": "Test-Only-Password-2026!"
            }, follow_redirects=False)
            assert login.status_code == 303

            dashboard = client.get("/")
            assert dashboard.status_code == 200 and "اطلاعات سرور" in dashboard.text
            csrf = re.search(r'name="csrf" value="([^\"]+)"', dashboard.text).group(1)
            created = client.post("/clients/create", data={
                "csrf": csrf, "name": "Automated Test User", "protocol": "vless",
                "quota_gb": "20", "duration_days": "30", "note": "test",
                "transport": "ws", "security": "tls",
            }, follow_redirects=False)
            assert created.status_code == 303
            listing = client.get("/clients")
            assert listing.status_code == 200
            assert "Automated Test User" in listing.text
            assert "vless://" in listing.text

        with TestSessionLocal() as db:
            saved = db.query(Client).filter(Client.name == "Automated Test User").one()
            assert saved.transport == "ws" and saved.security == "tls"
            assert decrypt_secret(saved.config_encrypted).startswith("vless://")
    finally:
        test_engine.dispose()
