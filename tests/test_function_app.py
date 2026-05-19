"""Unit tests for function_app MCP tool handlers."""
import asyncio
import json
import urllib.error
from io import BytesIO
from unittest.mock import MagicMock, patch

import pytest

import function_app


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_http_error(code: int, reason: str = "Error") -> urllib.error.HTTPError:
    hdrs = MagicMock()
    hdrs.get = lambda key, default=None: default
    return urllib.error.HTTPError(url="http://test", code=code, msg=reason, hdrs=hdrs, fp=BytesIO(b""))


def _make_url_error(reason: str = "Name resolution failed") -> urllib.error.URLError:
    return urllib.error.URLError(reason)


def _get_wrapper(tool):
    """Return the async wrapper function registered by the @app.mcp_tool() decorator."""
    return tool._function._func


def _run(tool, **kwargs):
    """Invoke a tool's wrapper with the given keyword arguments and return parsed JSON."""
    ctx = json.dumps({"arguments": kwargs})
    result = asyncio.run(_get_wrapper(tool)(ctx))
    return json.loads(result)


# ---------------------------------------------------------------------------
# search_cves
# ---------------------------------------------------------------------------


class TestSearchCves:
    def test_success_returns_data(self):
        payload = {"totalResults": 1, "vulnerabilities": [{"id": "CVE-2021-44228"}]}
        with patch.object(function_app.nvd_service, "search_cves", return_value=payload):
            result = _run(function_app.search_cves, keyword="log4j")
        assert result["totalResults"] == 1

    def test_empty_string_keyword_passes_none_to_service(self):
        """Empty-string params should become None before hitting the service."""
        captured = {}

        def mock_search(**kwargs):
            captured.update(kwargs)
            return {}

        with patch.object(function_app.nvd_service, "search_cves", side_effect=mock_search):
            _run(function_app.search_cves, keyword="")

        assert captured["keyword"] is None

    def test_empty_string_cve_id_becomes_none(self):
        captured = {}

        def mock_search(**kwargs):
            captured.update(kwargs)
            return {}

        with patch.object(function_app.nvd_service, "search_cves", side_effect=mock_search):
            _run(function_app.search_cves, cve_id="")

        assert captured["cve_id"] is None

    def test_has_kev_passed_through(self):
        captured = {}

        def mock_search(**kwargs):
            captured.update(kwargs)
            return {}

        with patch.object(function_app.nvd_service, "search_cves", side_effect=mock_search):
            _run(function_app.search_cves, has_kev=True)

        assert captured["has_kev"] is True

    def test_http_error_returns_error_json(self):
        with patch.object(function_app.nvd_service, "search_cves", side_effect=_make_http_error(429)):
            result = _run(function_app.search_cves)
        assert "error" in result
        assert result["status"] == 429

    def test_url_error_returns_error_json(self):
        with patch.object(function_app.nvd_service, "search_cves", side_effect=_make_url_error()):
            result = _run(function_app.search_cves)
        assert "error" in result
        assert "status" not in result

    def test_generic_exception_returns_internal_error(self):
        with patch.object(function_app.nvd_service, "search_cves", side_effect=RuntimeError("boom")):
            result = _run(function_app.search_cves)
        assert result == {"error": "Internal error"}

    def test_all_params_forwarded(self):
        captured = {}

        def mock_search(**kwargs):
            captured.update(kwargs)
            return {}

        with patch.object(function_app.nvd_service, "search_cves", side_effect=mock_search):
            _run(
                function_app.search_cves,
                keyword="apache",
                cve_id="CVE-2024-0001",
                cpe_name="cpe:2.3:a:apache:*",
                cvss_v3_severity="HIGH",
                cwe_id="CWE-79",
                pub_start_date="2024-01-01T00:00:00.000",
                pub_end_date="2024-03-31T23:59:59.999",
                last_mod_start_date="2024-01-01T00:00:00.000",
                last_mod_end_date="2024-03-31T23:59:59.999",
                has_kev=True,
                results_per_page=50,
                start_index=10,
            )

        assert captured["keyword"] == "apache"
        assert captured["cve_id"] == "CVE-2024-0001"
        assert captured["cvss_v3_severity"] == "HIGH"
        assert captured["has_kev"] is True
        assert captured["results_per_page"] == 50
        assert captured["start_index"] == 10


# ---------------------------------------------------------------------------
# get_cve
# ---------------------------------------------------------------------------


class TestGetCve:
    def test_success_returns_data(self):
        payload = {"vulnerabilities": [{"id": "CVE-2021-44228"}]}
        with patch.object(function_app.nvd_service, "get_cve", return_value=payload):
            result = _run(function_app.get_cve, cve_id="CVE-2021-44228")
        assert "vulnerabilities" in result

    def test_http_error_returns_error_json(self):
        with patch.object(function_app.nvd_service, "get_cve", side_effect=_make_http_error(404)):
            result = _run(function_app.get_cve, cve_id="CVE-9999-0000")
        assert "error" in result
        assert result["status"] == 404

    def test_url_error_returns_error_json(self):
        with patch.object(function_app.nvd_service, "get_cve", side_effect=_make_url_error()):
            result = _run(function_app.get_cve, cve_id="CVE-2021-44228")
        assert "error" in result

    def test_generic_exception_returns_internal_error(self):
        with patch.object(function_app.nvd_service, "get_cve", side_effect=ValueError("oops")):
            result = _run(function_app.get_cve, cve_id="CVE-2021-44228")
        assert result == {"error": "Internal error"}


# ---------------------------------------------------------------------------
# get_cve_history
# ---------------------------------------------------------------------------


class TestGetCveHistory:
    def test_success_returns_data(self):
        payload = {"totalResults": 2, "cveChanges": []}
        with patch.object(function_app.nvd_service, "get_cve_history", return_value=payload):
            result = _run(function_app.get_cve_history, cve_id="CVE-2021-44228")
        assert result["totalResults"] == 2

    def test_empty_string_params_become_none(self):
        captured = {}

        def mock_history(**kwargs):
            captured.update(kwargs)
            return {}

        with patch.object(function_app.nvd_service, "get_cve_history", side_effect=mock_history):
            _run(function_app.get_cve_history, cve_id="", event_name="")

        assert captured["cve_id"] is None
        assert captured["event_name"] is None

    def test_http_error_returns_error_json(self):
        with patch.object(function_app.nvd_service, "get_cve_history", side_effect=_make_http_error(500)):
            result = _run(function_app.get_cve_history)
        assert result["status"] == 500

    def test_url_error_returns_error_json(self):
        with patch.object(function_app.nvd_service, "get_cve_history", side_effect=_make_url_error()):
            result = _run(function_app.get_cve_history)
        assert "error" in result

    def test_generic_exception_returns_internal_error(self):
        with patch.object(function_app.nvd_service, "get_cve_history", side_effect=Exception("unexpected")):
            result = _run(function_app.get_cve_history)
        assert result == {"error": "Internal error"}

    def test_all_params_forwarded(self):
        captured = {}

        def mock_history(**kwargs):
            captured.update(kwargs)
            return {}

        with patch.object(function_app.nvd_service, "get_cve_history", side_effect=mock_history):
            _run(
                function_app.get_cve_history,
                cve_id="CVE-2024-0001",
                change_start_date="2024-01-01T00:00:00.000",
                change_end_date="2024-03-31T23:59:59.999",
                event_name="Initial Analysis",
                results_per_page=100,
                start_index=5,
            )

        assert captured["cve_id"] == "CVE-2024-0001"
        assert captured["event_name"] == "Initial Analysis"
        assert captured["results_per_page"] == 100


# ---------------------------------------------------------------------------
# search_cves_by_cpe
# ---------------------------------------------------------------------------


class TestSearchCvesByCpe:
    def test_success_returns_data(self):
        payload = {"totalResults": 3, "vulnerabilities": []}
        with patch.object(function_app.nvd_service, "search_cves", return_value=payload):
            result = _run(function_app.search_cves_by_cpe, cpe_name="cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
        assert result["totalResults"] == 3

    def test_passes_cpe_name_to_service(self):
        captured = {}

        def mock_search(**kwargs):
            captured.update(kwargs)
            return {}

        with patch.object(function_app.nvd_service, "search_cves", side_effect=mock_search):
            _run(function_app.search_cves_by_cpe, cpe_name="cpe:2.3:a:microsoft:windows:*")

        assert captured["cpe_name"] == "cpe:2.3:a:microsoft:windows:*"

    def test_pagination_params_forwarded(self):
        captured = {}

        def mock_search(**kwargs):
            captured.update(kwargs)
            return {}

        with patch.object(function_app.nvd_service, "search_cves", side_effect=mock_search):
            _run(function_app.search_cves_by_cpe, cpe_name="cpe:2.3:a:apache:*", results_per_page=50, start_index=20)

        assert captured["results_per_page"] == 50
        assert captured["start_index"] == 20

    def test_http_error_returns_error_json(self):
        with patch.object(function_app.nvd_service, "search_cves", side_effect=_make_http_error(503)):
            result = _run(function_app.search_cves_by_cpe, cpe_name="cpe:2.3:a:test:*")
        assert result["status"] == 503

    def test_url_error_returns_error_json(self):
        with patch.object(function_app.nvd_service, "search_cves", side_effect=_make_url_error()):
            result = _run(function_app.search_cves_by_cpe, cpe_name="cpe:2.3:a:test:*")
        assert "error" in result

    def test_generic_exception_returns_internal_error(self):
        with patch.object(function_app.nvd_service, "search_cves", side_effect=TypeError("bad type")):
            result = _run(function_app.search_cves_by_cpe, cpe_name="cpe:2.3:a:test:*")
        assert result == {"error": "Internal error"}


# ---------------------------------------------------------------------------
# get_recent_cves
# ---------------------------------------------------------------------------


class TestGetRecentCves:
    def test_success_default_7_days(self):
        payload = {"totalResults": 5}
        captured = {}

        def mock_search(**kwargs):
            captured.update(kwargs)
            return payload

        with patch.object(function_app.nvd_service, "search_cves", side_effect=mock_search):
            result = _run(function_app.get_recent_cves)

        assert result["totalResults"] == 5
        assert "pub_start_date" in captured
        assert "pub_end_date" in captured

    def test_days_clamped_min_to_1(self):
        captured = {}

        def mock_search(**kwargs):
            captured.update(kwargs)
            return {}

        with patch.object(function_app.nvd_service, "search_cves", side_effect=mock_search):
            _run(function_app.get_recent_cves, days=0)

        # With days clamped to 1, the range should be 1 day
        import datetime

        start = datetime.datetime.fromisoformat(captured["pub_start_date"].replace(".000", ""))
        end = datetime.datetime.fromisoformat(captured["pub_end_date"].replace(".000", ""))
        delta = end - start
        assert abs(delta.total_seconds() - 86400) < 60  # roughly 1 day

    def test_days_clamped_max_to_120(self):
        captured = {}

        def mock_search(**kwargs):
            captured.update(kwargs)
            return {}

        with patch.object(function_app.nvd_service, "search_cves", side_effect=mock_search):
            _run(function_app.get_recent_cves, days=999)

        import datetime

        start = datetime.datetime.fromisoformat(captured["pub_start_date"].replace(".000", ""))
        end = datetime.datetime.fromisoformat(captured["pub_end_date"].replace(".000", ""))
        delta = end - start
        assert abs(delta.total_seconds() - 120 * 86400) < 60  # roughly 120 days

    def test_severity_filter_forwarded(self):
        captured = {}

        def mock_search(**kwargs):
            captured.update(kwargs)
            return {}

        with patch.object(function_app.nvd_service, "search_cves", side_effect=mock_search):
            _run(function_app.get_recent_cves, cvss_v3_severity="CRITICAL")

        assert captured["cvss_v3_severity"] == "CRITICAL"

    def test_empty_severity_becomes_none(self):
        captured = {}

        def mock_search(**kwargs):
            captured.update(kwargs)
            return {}

        with patch.object(function_app.nvd_service, "search_cves", side_effect=mock_search):
            _run(function_app.get_recent_cves, cvss_v3_severity="")

        assert captured["cvss_v3_severity"] is None

    def test_has_kev_forwarded(self):
        captured = {}

        def mock_search(**kwargs):
            captured.update(kwargs)
            return {}

        with patch.object(function_app.nvd_service, "search_cves", side_effect=mock_search):
            _run(function_app.get_recent_cves, has_kev=True)

        assert captured["has_kev"] is True

    def test_http_error_returns_error_json(self):
        with patch.object(function_app.nvd_service, "search_cves", side_effect=_make_http_error(429)):
            result = _run(function_app.get_recent_cves)
        assert result["status"] == 429

    def test_url_error_returns_error_json(self):
        with patch.object(function_app.nvd_service, "search_cves", side_effect=_make_url_error()):
            result = _run(function_app.get_recent_cves)
        assert "error" in result

    def test_generic_exception_returns_internal_error(self):
        with patch.object(function_app.nvd_service, "search_cves", side_effect=Exception("bang")):
            result = _run(function_app.get_recent_cves)
        assert result == {"error": "Internal error"}


# ---------------------------------------------------------------------------
# search_cpes
# ---------------------------------------------------------------------------


class TestSearchCpes:
    def test_success_returns_data(self):
        payload = {"products": [{"cpe": {"cpeName": "cpe:2.3:a:apache:log4j:*"}}]}
        with patch.object(function_app.nvd_service, "search_cpes", return_value=payload):
            result = _run(function_app.search_cpes, keyword="apache")
        assert "products" in result

    def test_empty_keyword_becomes_none(self):
        captured = {}

        def mock_search(**kwargs):
            captured.update(kwargs)
            return {}

        with patch.object(function_app.nvd_service, "search_cpes", side_effect=mock_search):
            _run(function_app.search_cpes, keyword="")

        assert captured["keyword"] is None

    def test_empty_cpe_match_string_becomes_none(self):
        captured = {}

        def mock_search(**kwargs):
            captured.update(kwargs)
            return {}

        with patch.object(function_app.nvd_service, "search_cpes", side_effect=mock_search):
            _run(function_app.search_cpes, cpe_match_string="")

        assert captured["cpe_match_string"] is None

    def test_pagination_params_forwarded(self):
        captured = {}

        def mock_search(**kwargs):
            captured.update(kwargs)
            return {}

        with patch.object(function_app.nvd_service, "search_cpes", side_effect=mock_search):
            _run(function_app.search_cpes, results_per_page=100, start_index=50)

        assert captured["results_per_page"] == 100
        assert captured["start_index"] == 50

    def test_http_error_returns_error_json(self):
        with patch.object(function_app.nvd_service, "search_cpes", side_effect=_make_http_error(502)):
            result = _run(function_app.search_cpes, keyword="openssl")
        assert result["status"] == 502

    def test_url_error_returns_error_json(self):
        with patch.object(function_app.nvd_service, "search_cpes", side_effect=_make_url_error()):
            result = _run(function_app.search_cpes, keyword="openssl")
        assert "error" in result

    def test_generic_exception_returns_internal_error(self):
        with patch.object(function_app.nvd_service, "search_cpes", side_effect=RuntimeError("fail")):
            result = _run(function_app.search_cpes, keyword="openssl")
        assert result == {"error": "Internal error"}


# ---------------------------------------------------------------------------
# get_kev
# ---------------------------------------------------------------------------


def _kev_catalog() -> dict:
    return {
        "catalogVersion": "2024.05.01",
        "dateReleased": "2024-05-01T12:00:00Z",
        "vulnerabilities": [
            {
                "cveID": "CVE-2021-44228",
                "vendorProject": "Apache",
                "product": "Log4j",
                "vulnerabilityName": "Log4Shell RCE",
                "dateAdded": "2021-12-10",
                "knownRansomwareCampaignUse": "Known",
            },
            {
                "cveID": "CVE-2022-0001",
                "vendorProject": "Microsoft",
                "product": "Windows",
                "vulnerabilityName": "Spoofing Vulnerability",
                "dateAdded": "2022-01-15",
                "knownRansomwareCampaignUse": "Unknown",
            },
            {
                "cveID": "CVE-2023-9999",
                "vendorProject": "Cisco",
                "product": "IOS",
                "vulnerabilityName": "Buffer Overflow",
                "dateAdded": "2023-06-20",
                "knownRansomwareCampaignUse": "Unknown",
            },
        ],
    }


class TestGetKev:
    def test_success_returns_catalog_summary(self):
        with patch.object(function_app.nvd_service, "get_kev", return_value=_kev_catalog()):
            result = _run(function_app.get_kev)
        assert result["catalogVersion"] == "2024.05.01"
        assert result["matched"] == 3
        assert result["showing"] == 3

    def test_results_sorted_by_date_desc(self):
        with patch.object(function_app.nvd_service, "get_kev", return_value=_kev_catalog()):
            result = _run(function_app.get_kev)
        dates = [v["dateAdded"] for v in result["vulnerabilities"]]
        assert dates == sorted(dates, reverse=True)

    def test_results_per_page_limits_output(self):
        with patch.object(function_app.nvd_service, "get_kev", return_value=_kev_catalog()):
            result = _run(function_app.get_kev, results_per_page=1)
        assert result["showing"] == 1
        assert result["matched"] == 3

    def test_results_per_page_clamped_min(self):
        with patch.object(function_app.nvd_service, "get_kev", return_value=_kev_catalog()):
            result = _run(function_app.get_kev, results_per_page=0)
        # 0 → max(1, 0) → 1
        assert result["showing"] == 1

    def test_results_per_page_clamped_max(self):
        with patch.object(function_app.nvd_service, "get_kev", return_value=_kev_catalog()):
            result = _run(function_app.get_kev, results_per_page=9999)
        # 9999 → min(9999, 2000) → 2000, but catalog only has 3
        assert result["showing"] == 3

    def test_ransomware_count_calculated(self):
        with patch.object(function_app.nvd_service, "get_kev", return_value=_kev_catalog()):
            result = _run(function_app.get_kev)
        assert result["ransomwareAssociated"] == 1

    def test_since_filter_excludes_older_entries(self):
        with patch.object(function_app.nvd_service, "get_kev", return_value=_kev_catalog()):
            result = _run(function_app.get_kev, since="2022-01-01")
        cve_ids = [v["cveID"] for v in result["vulnerabilities"]]
        assert "CVE-2021-44228" not in cve_ids  # dateAdded 2021-12-10 < 2022-01-01
        assert result["matched"] == 2

    def test_since_filter_includes_exact_date(self):
        with patch.object(function_app.nvd_service, "get_kev", return_value=_kev_catalog()):
            result = _run(function_app.get_kev, since="2022-01-15")
        cve_ids = [v["cveID"] for v in result["vulnerabilities"]]
        assert "CVE-2022-0001" in cve_ids

    def test_ransomware_only_filter(self):
        with patch.object(function_app.nvd_service, "get_kev", return_value=_kev_catalog()):
            result = _run(function_app.get_kev, ransomware_only=True)
        assert result["matched"] == 1
        assert result["vulnerabilities"][0]["cveID"] == "CVE-2021-44228"

    def test_keyword_filter_by_vendor(self):
        with patch.object(function_app.nvd_service, "get_kev", return_value=_kev_catalog()):
            result = _run(function_app.get_kev, keyword="apache")
        assert result["matched"] == 1
        assert result["vulnerabilities"][0]["cveID"] == "CVE-2021-44228"

    def test_keyword_filter_by_product(self):
        with patch.object(function_app.nvd_service, "get_kev", return_value=_kev_catalog()):
            result = _run(function_app.get_kev, keyword="windows")
        assert result["matched"] == 1
        assert result["vulnerabilities"][0]["cveID"] == "CVE-2022-0001"

    def test_keyword_filter_by_vulnerability_name(self):
        with patch.object(function_app.nvd_service, "get_kev", return_value=_kev_catalog()):
            result = _run(function_app.get_kev, keyword="log4shell")
        assert result["matched"] == 1

    def test_keyword_filter_by_cve_id(self):
        with patch.object(function_app.nvd_service, "get_kev", return_value=_kev_catalog()):
            result = _run(function_app.get_kev, keyword="CVE-2023-9999")
        assert result["matched"] == 1

    def test_keyword_filter_case_insensitive(self):
        with patch.object(function_app.nvd_service, "get_kev", return_value=_kev_catalog()):
            result = _run(function_app.get_kev, keyword="APACHE")
        assert result["matched"] == 1

    def test_keyword_no_match_returns_empty(self):
        with patch.object(function_app.nvd_service, "get_kev", return_value=_kev_catalog()):
            result = _run(function_app.get_kev, keyword="xyznonexistent")
        assert result["matched"] == 0
        assert result["vulnerabilities"] == []

    def test_combined_filters(self):
        """since + ransomware_only should combine."""
        with patch.object(function_app.nvd_service, "get_kev", return_value=_kev_catalog()):
            result = _run(function_app.get_kev, since="2022-01-01", ransomware_only=True)
        # CVE-2021-44228 has ransomware but dateAdded 2021-12-10 < 2022-01-01 → excluded
        assert result["matched"] == 0

    def test_http_error_returns_error_json(self):
        with patch.object(function_app.nvd_service, "get_kev", side_effect=_make_http_error(503)):
            result = _run(function_app.get_kev)
        assert result["status"] == 503

    def test_url_error_returns_error_json(self):
        with patch.object(function_app.nvd_service, "get_kev", side_effect=_make_url_error()):
            result = _run(function_app.get_kev)
        assert "error" in result

    def test_generic_exception_returns_internal_error(self):
        with patch.object(function_app.nvd_service, "get_kev", side_effect=Exception("chaos")):
            result = _run(function_app.get_kev)
        assert result == {"error": "Internal error"}
