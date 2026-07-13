#!/usr/bin/env python3
"""Focused tests for static JavaScript config API-base inventory."""

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pipeline.config_base_inventory import extract_config_base_inventory


def by_url(items):
    return {item["url"]: item for item in items}


def test_serverconfig_pattern_and_deterministic_dedup():
    source_asset = "http://192.0.2.10:8080/serverconfig.js?v=7"
    source_page = "http://192.0.2.10:8080/app/index.html"
    first = """
        var WORKURL = "http://192.0.2.10:8877//synthetic-api/catalog/";
        window.USERURL = 'http://192.0.2.10:8877//main//userapi';
        window.apiconfig.ACCOUNTURL = "http://192.0.2.10:8877//synthetic-api/catalog";
        window.apiconfig["CATALOGAPIURL"] = "http://192.0.2.10:8877//synthetic-api/catalog/";
    """
    second = """
        window.apiconfig["CATALOGAPIURL"] = "http://192.0.2.10:8877//synthetic-api/catalog/";
        window.apiconfig.ACCOUNTURL = "http://192.0.2.10:8877//synthetic-api/catalog";
        window.USERURL = 'http://192.0.2.10:8877//main//userapi';
        var WORKURL = "http://192.0.2.10:8877//synthetic-api/catalog/";
    """

    one = extract_config_base_inventory(first, source_asset, source_page)
    two = extract_config_base_inventory(second, source_asset, source_page)
    assert one == two
    assert len(one) == 2, one

    items = by_url(one)
    work = items["http://192.0.2.10:8877/synthetic-api/catalog"]
    assert work["origin"] == "http://192.0.2.10:8877"
    assert work["path_prefix"] == "/synthetic-api/catalog"
    assert work["config_keys"] == ["ACCOUNTURL", "CATALOGAPIURL", "WORKURL"]
    assert work["same_host"] is True
    assert work["active_eligible"] is True
    assert work["active_scope_recommendation"] == "same_host"


def test_lower_camel_vue_and_apiconfig_keys():
    script = """
        const config = {
          workUrl: "https://front.example.test/work",
          userurl: "https://front.example.test/user",
          accountURL: "https://front.example.test/account",
          catalogApiUrl: "https://front.example.test/catalog",
          baseURL: "https://front.example.test/base",
          API_URL: "https://front.example.test/api",
          VUE_APP_PROFILE_URL: "https://front.example.test/profile"
        };
        window.apiconfig = {
          serviceUrl: "https://front.example.test/service"
        };
    """
    items = extract_config_base_inventory(
        script,
        source_asset="https://front.example.test/assets/serverconfig.js",
        source_page="https://front.example.test/portal/",
    )
    urls = {item["url"] for item in items}
    assert urls == {
        "https://front.example.test/account",
        "https://front.example.test/api",
        "https://front.example.test/base",
        "https://front.example.test/catalog",
        "https://front.example.test/profile",
        "https://front.example.test/service",
        "https://front.example.test/user",
        "https://front.example.test/work",
    }, items
    assert all(item["active_eligible"] for item in items)


def test_rejects_malformed_secret_and_static_values():
    script = r'''
        WORKURL = "ftp://front.example.test/api";
        USERURL = "//front.example.test/api";
        ACCOUNTURL = "http://user:password@front.example.test/api";
        CATALOGAPIURL = "http://front.example.test/api?token=secret";
        API_URL = "http://front.example.test/api#admin";
        baseURL = "http://front.example.test/static/serverconfig.js";
        VUE_APP_DATA_URL = "http://front.example.test/config.json";
        window.apiconfig.badUrl = "http://bad host/api";
        window.apiconfig.emptyUrl = "http:///api";
        window.apiconfig.portUrl = "http://front.example.test:bad/api";
        window.apiconfig.logoUrl = "http://front.example.test/assets/logo.png";
    '''
    assert extract_config_base_inventory(
        script,
        source_page="http://front.example.test/",
    ) == []


def test_external_and_private_hosts_are_inventory_only():
    script = """
        API_URL = "https://api.other.example/v1";
        USERURL = "http://10.20.30.40:9000/internal/api";
        WORKURL = "https://front.example.test:9443/same-host/api";
    """
    items = by_url(extract_config_base_inventory(
        script,
        source_asset="https://front.example.test/serverconfig.js",
        source_page="https://front.example.test/app/",
    ))
    assert items["https://api.other.example/v1"]["active_scope_recommendation"] == "inventory_only"
    assert items["http://10.20.30.40:9000/internal/api"]["active_scope_recommendation"] == "inventory_only"
    assert items["https://front.example.test:9443/same-host/api"]["active_scope_recommendation"] == "same_host"
    assert items["http://10.20.30.40:9000/internal/api"]["path_prefix"] == "/internal/api"


def test_provenance_confidence_and_json_serialization():
    source_asset = "http://[2001:db8::10]:8080/static/serverconfig.js"
    source_page = "http://[2001:db8::10]:8080/app/"
    items = extract_config_base_inventory(
        r'''window.apiconfig.API_URL = "http:\/\/[2001:db8::10]:8877\/\/api\/v1\/";''',
        source_asset=source_asset,
        source_page=source_page,
    )
    assert len(items) == 1, items
    item = items[0]
    assert item["url"] == "http://[2001:db8::10]:8877/api/v1"
    assert item["source"] == "js_config_base"
    assert item["source_asset"] == source_asset
    assert item["source_page"] == source_page
    assert item["source_origin"] == "http://[2001:db8::10]:8080"
    assert item["confidence"] == 0.92
    assert item["same_host"] is True
    encoded = json.dumps(items, sort_keys=True)
    assert "js_config_base" in encoded


def main():
    tests = [
        test_serverconfig_pattern_and_deterministic_dedup,
        test_lower_camel_vue_and_apiconfig_keys,
        test_rejects_malformed_secret_and_static_values,
        test_external_and_private_hosts_are_inventory_only,
        test_provenance_confidence_and_json_serialization,
    ]
    for test in tests:
        test()
        print("PASS", test.__name__)
    print("CONFIG BASE INVENTORY TEST PASS")


if __name__ == "__main__":
    main()
