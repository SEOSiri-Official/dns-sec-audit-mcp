# tests/test_dns_sec.py
import json
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.main_server import (
    audit_dns_records,
    check_soa_expiry_health,
    audit_http_security_headers,
    check_ssl_tls_certificate,
    validate_well_known_security_txt,
    validate_well_known_llm_txt,
    calculate_technical_seo_security_score,
    sanitize_audit_payload,
    get_live_dns_throughput_metrics,
    get_dns_server_specifications
)


def test_1_dns_records():
    res = json.loads(audit_dns_records("seosiri.com"))
    assert "status" in res


def test_2_soa_health():
    res = json.loads(check_soa_expiry_health("seosiri.com"))
    assert res["status"] == "HEALTHY"


def test_3_security_headers():
    res = json.loads(audit_http_security_headers("https://seosiri.com"))
    assert "status" in res


def test_4_ssl_certificate():
    res = json.loads(check_ssl_tls_certificate("seosiri.com"))
    assert "status" in res


def test_5_security_txt():
    res = json.loads(validate_well_known_security_txt("seosiri.com"))
    assert "status" in res


def test_6_llm_txt():
    res = json.loads(validate_well_known_llm_txt("seosiri.com"))
    assert "status" in res


def test_7_technical_score():
    res = json.loads(calculate_technical_seo_security_score(True, True, True, 90.0))
    assert res["status"] == "SCORED"
    assert res["aggregate_score"] == 97.0


def test_8_sanitize_payload():
    res = json.loads(sanitize_audit_payload("<div>test</div>"))
    assert res["status"] == "SANITIZED"


def test_9_throughput_metrics():
    res = json.loads(get_live_dns_throughput_metrics())
    assert res["status"] == "HEALTHY"


def test_10_server_specs():
    res = json.loads(get_dns_server_specifications())
    assert res["total_tools"] == 10