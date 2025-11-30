import types
import builtins
import json
import main

class FakeResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload
    def json(self):
        return self._payload

def test_get_ip_info_ipv4_success(monkeypatch):
    def fake_get(url, timeout=5):
        assert "ipapi.co/ipv4/json" in url
        return FakeResponse(200, {
            "ip": "1.2.3.4",
            "city": "City",
            "region": "Region",
            "country_name": "Country",
            "country_code": "CC",
            "org": "ISP Inc",
            "asn": "AS1234",
        })
    import requests
    monkeypatch.setattr(requests, "get", fake_get)
    res = main.get_ip_info("ipv4")
    assert res["Source"] == "ipapi.co"
    assert res["IP Version"] == "IPV4"
    assert res["IP Address"] == "1.2.3.4"

def test_get_ip_info_rate_limited_fallback_success(monkeypatch):
    def fake_get(url, timeout=5):
        if "ipapi.co/ipv6/json" in url:
            return FakeResponse(429, {})
        if "ipinfo.io/json" in url:
            return FakeResponse(200, {
                "ip": "2001:db8::1",
                "city": "V6City",
                "region": "V6Region",
                "country": "V6",
                "org": "ISPv6",
                "asn": "ASV6",
            })
        raise AssertionError("Unexpected URL: " + url)
    import requests
    monkeypatch.setattr(requests, "get", fake_get)
    res = main.get_ip_info("ipv6")
    assert res["Source"] == "ipinfo.io"
    assert res["IP Version"] == "IPV6"
    assert res["IP Address"] == "2001:db8::1"

def test_get_ip_info_error_returns_none(monkeypatch):
    import requests
    def fake_get(url, timeout=5):
        raise requests.RequestException("network down")
    monkeypatch.setattr(requests, "get", fake_get)
    assert main.get_ip_info("ipv4") is None

def test_detect_ipv6_only(monkeypatch):
    def fake_get_ip_info(version):
        if version == "ipv4":
            return None
        return {"IP Address": "2001:db8::2"}
    monkeypatch.setattr(main, "get_ip_info", fake_get_ip_info)
    ipv4, ipv6, ipv6_only = main.detect_ipv6_only()
    assert ipv4 is None
    assert ipv6["IP Address"] == "2001:db8::2"
    assert ipv6_only is True

def test_history_save_and_load(tmp_path, monkeypatch):
    hist_file = tmp_path / "ip_history.json"
    monkeypatch.setattr(main, "HISTORY_FILE", str(hist_file))
    entry1 = {"type": "ipv4", "IP Address": "1.2.3.4", "Timestamp": "t1"}
    entry2 = {"type": "ipv6", "IP Address": "2001:db8::1", "Timestamp": "t2"}
    main.save_history(entry1)
    main.save_history(entry2)
    history = main.load_history()
    assert len(history) == 2
    assert history[0]["IP Address"] == "1.2.3.4"
    assert history[1]["IP Address"] == "2001:db8::1"