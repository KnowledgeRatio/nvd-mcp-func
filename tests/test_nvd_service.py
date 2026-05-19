"""Unit tests for NVDService."""
import json
import urllib.error
from io import BytesIO
from unittest.mock import MagicMock, call, patch

import pytest

from nvd_service import NVDService

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_response(data: dict) -> MagicMock:
    """Return a mock that behaves like the context manager from urlopen."""
    body = json.dumps(data).encode("utf-8")
    mock_resp = MagicMock()
    mock_resp.read.return_value = body
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


def _make_http_error(code: int, reason: str = "Error", headers: dict | None = None) -> urllib.error.HTTPError:
    hdrs = MagicMock()
    hdrs.get = lambda key, default=None: (headers or {}).get(key, default)
    return urllib.error.HTTPError(url="http://test", code=code, msg=reason, hdrs=hdrs, fp=BytesIO(b""))


def _make_url_error(reason: str = "Name resolution failed") -> urllib.error.URLError:
    return urllib.error.URLError(reason)


def _fresh_service(**env_overrides) -> NVDService:
    """Create a new NVDService with any extra environment patches applied."""
    env = {"NVD_API_KEY": "", "NVD_HTTP_TIMEOUT_SECONDS": "15", "NVD_HTTP_MAX_RETRIES": "3"}
    env.update(env_overrides)
    with patch.dict("os.environ", env, clear=False):
        return NVDService()


# ---------------------------------------------------------------------------
# _parse_positive_float
# ---------------------------------------------------------------------------


class TestParsePositiveFloat:
    def test_none_returns_default(self):
        assert NVDService._parse_positive_float(None, 10.0) == 10.0

    def test_valid_positive_float(self):
        assert NVDService._parse_positive_float("3.5", 10.0) == 3.5

    def test_integer_string(self):
        assert NVDService._parse_positive_float("30", 10.0) == 30.0

    def test_zero_returns_default(self):
        assert NVDService._parse_positive_float("0", 10.0) == 10.0

    def test_negative_returns_default(self):
        assert NVDService._parse_positive_float("-1.0", 10.0) == 10.0

    def test_invalid_string_returns_default(self):
        assert NVDService._parse_positive_float("abc", 10.0) == 10.0

    def test_empty_string_returns_default(self):
        assert NVDService._parse_positive_float("", 10.0) == 10.0

    def test_very_small_positive(self):
        assert NVDService._parse_positive_float("0.001", 10.0) == pytest.approx(0.001)

    def test_default_unchanged_when_valid(self):
        result = NVDService._parse_positive_float("5.0", 99.0)
        assert result == 5.0


# ---------------------------------------------------------------------------
# _parse_positive_int
# ---------------------------------------------------------------------------


class TestParsePositiveInt:
    def test_none_returns_default(self):
        assert NVDService._parse_positive_int(None, 5) == 5

    def test_valid_positive_int(self):
        assert NVDService._parse_positive_int("3", 5) == 3

    def test_one_is_valid(self):
        assert NVDService._parse_positive_int("1", 5) == 1

    def test_zero_returns_default(self):
        # 0 < 1, so treated as invalid
        assert NVDService._parse_positive_int("0", 5) == 5

    def test_negative_returns_default(self):
        assert NVDService._parse_positive_int("-2", 5) == 5

    def test_invalid_string_returns_default(self):
        assert NVDService._parse_positive_int("xyz", 5) == 5

    def test_empty_string_returns_default(self):
        assert NVDService._parse_positive_int("", 5) == 5

    def test_float_string_returns_default(self):
        # int("3.5") raises ValueError, so default is used
        assert NVDService._parse_positive_int("3.5", 5) == 5


# ---------------------------------------------------------------------------
# _retry_delay
# ---------------------------------------------------------------------------


class TestRetryDelay:
    def test_exponential_attempt_0(self):
        # 0.5 * 2**0 = 0.5
        assert NVDService._retry_delay(0) == pytest.approx(0.5)

    def test_exponential_attempt_1(self):
        # 0.5 * 2**1 = 1.0
        assert NVDService._retry_delay(1) == pytest.approx(1.0)

    def test_exponential_attempt_4(self):
        # 0.5 * 2**4 = 8.0
        assert NVDService._retry_delay(4) == pytest.approx(8.0)

    def test_exponential_capped_at_10(self):
        # 0.5 * 2**5 = 16 → min(16, 10) = 10
        assert NVDService._retry_delay(5) == pytest.approx(10.0)

    def test_exponential_large_attempt_still_capped(self):
        assert NVDService._retry_delay(100) == pytest.approx(10.0)

    def test_retry_after_returns_value(self):
        assert NVDService._retry_delay(0, "5") == pytest.approx(5.0)

    def test_retry_after_float_string(self):
        assert NVDService._retry_delay(0, "2.5") == pytest.approx(2.5)

    def test_retry_after_capped_at_30(self):
        assert NVDService._retry_delay(0, "60") == pytest.approx(30.0)

    def test_retry_after_zero_allowed(self):
        assert NVDService._retry_delay(0, "0") == pytest.approx(0.0)

    def test_retry_after_invalid_falls_back_to_exponential(self):
        assert NVDService._retry_delay(0, "invalid") == pytest.approx(0.5)

    def test_retry_after_negative_falls_back_to_exponential(self):
        # -1 < 0, so falls back to exponential
        assert NVDService._retry_delay(0, "-1") == pytest.approx(0.5)

    def test_retry_after_none_uses_exponential(self):
        assert NVDService._retry_delay(0, None) == pytest.approx(0.5)


# ---------------------------------------------------------------------------
# NVDService.__init__
# ---------------------------------------------------------------------------


class TestNVDServiceInit:
    def test_defaults_no_env(self, monkeypatch):
        monkeypatch.delenv("NVD_API_KEY", raising=False)
        monkeypatch.delenv("NVD_HTTP_TIMEOUT_SECONDS", raising=False)
        monkeypatch.delenv("NVD_HTTP_MAX_RETRIES", raising=False)
        svc = NVDService()
        assert svc._api_key is None
        assert svc._timeout_seconds == 15.0
        assert svc._max_retries == 3

    def test_with_api_key(self, monkeypatch):
        monkeypatch.setenv("NVD_API_KEY", "my-secret-key")
        monkeypatch.delenv("NVD_HTTP_TIMEOUT_SECONDS", raising=False)
        monkeypatch.delenv("NVD_HTTP_MAX_RETRIES", raising=False)
        svc = NVDService()
        assert svc._api_key == "my-secret-key"

    def test_empty_api_key_treated_as_none(self, monkeypatch):
        monkeypatch.setenv("NVD_API_KEY", "")
        svc = NVDService()
        assert svc._api_key is None

    def test_custom_timeout(self, monkeypatch):
        monkeypatch.delenv("NVD_API_KEY", raising=False)
        monkeypatch.setenv("NVD_HTTP_TIMEOUT_SECONDS", "30")
        monkeypatch.delenv("NVD_HTTP_MAX_RETRIES", raising=False)
        svc = NVDService()
        assert svc._timeout_seconds == 30.0

    def test_custom_retries(self, monkeypatch):
        monkeypatch.delenv("NVD_API_KEY", raising=False)
        monkeypatch.delenv("NVD_HTTP_TIMEOUT_SECONDS", raising=False)
        monkeypatch.setenv("NVD_HTTP_MAX_RETRIES", "7")
        svc = NVDService()
        assert svc._max_retries == 7

    def test_invalid_timeout_uses_default(self, monkeypatch):
        monkeypatch.delenv("NVD_API_KEY", raising=False)
        monkeypatch.setenv("NVD_HTTP_TIMEOUT_SECONDS", "not-a-number")
        svc = NVDService()
        assert svc._timeout_seconds == 15.0

    def test_zero_retries_uses_default(self, monkeypatch):
        monkeypatch.delenv("NVD_API_KEY", raising=False)
        monkeypatch.setenv("NVD_HTTP_MAX_RETRIES", "0")
        svc = NVDService()
        assert svc._max_retries == 3

    def test_negative_retries_uses_default(self, monkeypatch):
        monkeypatch.delenv("NVD_API_KEY", raising=False)
        monkeypatch.setenv("NVD_HTTP_MAX_RETRIES", "-1")
        svc = NVDService()
        assert svc._max_retries == 3


# ---------------------------------------------------------------------------
# NVDService._get
# ---------------------------------------------------------------------------


class TestNVDServiceGet:
    def setup_method(self):
        self.svc = _fresh_service()

    def test_success_returns_parsed_json(self):
        payload = {"totalResults": 1, "vulnerabilities": []}
        with patch("urllib.request.urlopen", return_value=_make_response(payload)) as mock_open:
            result = self.svc._get("https://example.com", {"foo": "bar"})
        assert result == payload
        mock_open.assert_called_once()

    def test_url_includes_query_params(self):
        payload = {}
        with patch("urllib.request.urlopen", return_value=_make_response(payload)):
            self.svc._get("https://example.com/api", {"a": "1", "b": "2"})

    def test_api_key_header_added_when_present(self, monkeypatch):
        monkeypatch.setenv("NVD_API_KEY", "secret")
        svc = NVDService()
        payload = {}
        captured_requests = []

        def fake_urlopen(req, timeout=None):
            captured_requests.append(req)
            return _make_response(payload)

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            svc._get("https://example.com", {})

        assert captured_requests[0].get_header("Apikey") == "secret"

    def test_no_api_key_header_when_absent(self, monkeypatch):
        monkeypatch.delenv("NVD_API_KEY", raising=False)
        svc = NVDService()
        payload = {}
        captured_requests = []

        def fake_urlopen(req, timeout=None):
            captured_requests.append(req)
            return _make_response(payload)

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            svc._get("https://example.com", {})

        assert captured_requests[0].get_header("Apikey") is None

    def test_non_retryable_http_error_raises_immediately(self):
        err = _make_http_error(404)
        with patch("urllib.request.urlopen", side_effect=err):
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                self.svc._get("https://example.com", {})
        assert exc_info.value.code == 404

    def test_non_retryable_403_raises_immediately(self):
        err = _make_http_error(403, "Forbidden")
        with patch("urllib.request.urlopen", side_effect=err), patch("time.sleep") as mock_sleep:
            with pytest.raises(urllib.error.HTTPError):
                self.svc._get("https://example.com", {})
        mock_sleep.assert_not_called()

    def test_retryable_429_retries_then_raises(self):
        err = _make_http_error(429, "Too Many Requests")
        with patch("urllib.request.urlopen", side_effect=err), patch("time.sleep") as mock_sleep:
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                self.svc._get("https://example.com", {})
        assert exc_info.value.code == 429
        # max_retries=3, so sleep is called on attempts 0 and 1 (not on last attempt)
        assert mock_sleep.call_count == 2

    def test_retryable_500_retries(self):
        err = _make_http_error(500)
        with patch("urllib.request.urlopen", side_effect=err), patch("time.sleep"):
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                self.svc._get("https://example.com", {})
        assert exc_info.value.code == 500

    def test_retryable_503_retries(self):
        err = _make_http_error(503)
        with patch("urllib.request.urlopen", side_effect=err), patch("time.sleep"):
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                self.svc._get("https://example.com", {})
        assert exc_info.value.code == 503

    def test_retry_after_header_respected(self):
        err = _make_http_error(429, headers={"Retry-After": "7"})
        with patch("urllib.request.urlopen", side_effect=err), patch("time.sleep") as mock_sleep:
            with pytest.raises(urllib.error.HTTPError):
                self.svc._get("https://example.com", {})
        for sleep_call in mock_sleep.call_args_list:
            assert sleep_call == call(7.0)

    def test_succeeds_after_transient_error(self):
        payload = {"totalResults": 0}
        err = _make_http_error(503)
        responses = [err, _make_response(payload)]
        with patch("urllib.request.urlopen", side_effect=responses), patch("time.sleep"):
            result = self.svc._get("https://example.com", {})
        assert result == payload

    def test_url_error_retries_then_raises(self):
        err = _make_url_error("Connection refused")
        with patch("urllib.request.urlopen", side_effect=err), patch("time.sleep") as mock_sleep:
            with pytest.raises(urllib.error.URLError):
                self.svc._get("https://example.com", {})
        assert mock_sleep.call_count == 2

    def test_url_error_succeeds_after_retry(self):
        payload = {"result": "ok"}
        network_err = _make_url_error("Timeout")
        with patch("urllib.request.urlopen", side_effect=[network_err, _make_response(payload)]), patch("time.sleep"):
            result = self.svc._get("https://example.com", {})
        assert result == payload

    def test_max_retries_one_does_not_sleep_on_retryable(self):
        """With max_retries=1, first failure is also last attempt – no sleep."""
        svc = _fresh_service(NVD_HTTP_MAX_RETRIES="1")
        err = _make_http_error(429)
        with patch("urllib.request.urlopen", side_effect=err), patch("time.sleep") as mock_sleep:
            with pytest.raises(urllib.error.HTTPError):
                svc._get("https://example.com", {})
        mock_sleep.assert_not_called()

    def test_no_params_builds_plain_url(self):
        payload = {}
        with patch("urllib.request.urlopen", return_value=_make_response(payload)) as mock_open:
            self.svc._get("https://example.com/api", {})
        req = mock_open.call_args[0][0]
        assert req.full_url == "https://example.com/api"


# ---------------------------------------------------------------------------
# NVDService.search_cves
# ---------------------------------------------------------------------------


class TestSearchCves:
    def setup_method(self):
        self.svc = _fresh_service()

    def _call(self, **kwargs):
        captured = {}

        def fake_get(url, params):
            captured.update(params)
            captured["_url"] = url
            return {"totalResults": 0}

        self.svc._get = fake_get
        self.svc.search_cves(**kwargs)
        return captured

    def test_default_params_only(self):
        params = self._call()
        assert params["resultsPerPage"] == "20"
        assert params["startIndex"] == "0"
        assert "keywordSearch" not in params

    def test_keyword(self):
        params = self._call(keyword="log4j")
        assert params["keywordSearch"] == "log4j"

    def test_cve_id(self):
        params = self._call(cve_id="CVE-2021-44228")
        assert params["cveId"] == "CVE-2021-44228"

    def test_cpe_name(self):
        params = self._call(cpe_name="cpe:2.3:a:apache:log4j:*")
        assert params["cpeName"] == "cpe:2.3:a:apache:log4j:*"

    def test_cvss_v3_severity_uppercased(self):
        params = self._call(cvss_v3_severity="critical")
        assert params["cvssV3Severity"] == "CRITICAL"

    def test_cvss_v3_severity_already_upper(self):
        params = self._call(cvss_v3_severity="HIGH")
        assert params["cvssV3Severity"] == "HIGH"

    def test_cwe_id(self):
        params = self._call(cwe_id="CWE-79")
        assert params["cweId"] == "CWE-79"

    def test_pub_start_date(self):
        params = self._call(pub_start_date="2024-01-01T00:00:00.000")
        assert params["pubStartDate"] == "2024-01-01T00:00:00.000"

    def test_pub_end_date(self):
        params = self._call(pub_end_date="2024-03-31T23:59:59.999")
        assert params["pubEndDate"] == "2024-03-31T23:59:59.999"

    def test_last_mod_start_date(self):
        params = self._call(last_mod_start_date="2024-01-01T00:00:00.000")
        assert params["lastModStartDate"] == "2024-01-01T00:00:00.000"

    def test_last_mod_end_date(self):
        params = self._call(last_mod_end_date="2024-01-31T23:59:59.999")
        assert params["lastModEndDate"] == "2024-01-31T23:59:59.999"

    def test_has_kev_true(self):
        params = self._call(has_kev=True)
        assert "hasKev" in params
        assert params["hasKev"] == ""

    def test_has_kev_false_omits_param(self):
        params = self._call(has_kev=False)
        assert "hasKev" not in params

    def test_results_per_page_clamped_min(self):
        params = self._call(results_per_page=0)
        assert params["resultsPerPage"] == "1"

    def test_results_per_page_clamped_max(self):
        params = self._call(results_per_page=9999)
        assert params["resultsPerPage"] == "2000"

    def test_results_per_page_valid(self):
        params = self._call(results_per_page=50)
        assert params["resultsPerPage"] == "50"

    def test_start_index_negative_clamped(self):
        params = self._call(start_index=-10)
        assert params["startIndex"] == "0"

    def test_start_index_valid(self):
        params = self._call(start_index=100)
        assert params["startIndex"] == "100"

    def test_calls_cve_url(self):
        params = self._call()
        assert "nvd.nist.gov" in params["_url"]
        assert "cves" in params["_url"]

    def test_none_optional_params_omitted(self):
        params = self._call(keyword=None, cve_id=None, cpe_name=None, cvss_v3_severity=None)
        for key in ("keywordSearch", "cveId", "cpeName", "cvssV3Severity"):
            assert key not in params


# ---------------------------------------------------------------------------
# NVDService.get_cve
# ---------------------------------------------------------------------------


class TestGetCve:
    def setup_method(self):
        self.svc = _fresh_service()

    def test_passes_cve_id_param(self):
        captured = {}

        def fake_get(url, params):
            captured.update(params)
            return {"vulnerabilities": []}

        self.svc._get = fake_get
        self.svc.get_cve("CVE-2021-44228")
        assert captured["cveId"] == "CVE-2021-44228"

    def test_calls_cve_url(self):
        captured = {}

        def fake_get(url, params):
            captured["url"] = url
            return {}

        self.svc._get = fake_get
        self.svc.get_cve("CVE-2021-44228")
        assert "cves" in captured["url"]


# ---------------------------------------------------------------------------
# NVDService.search_cpes
# ---------------------------------------------------------------------------


class TestSearchCpes:
    def setup_method(self):
        self.svc = _fresh_service()

    def _call(self, **kwargs):
        captured = {}

        def fake_get(url, params):
            captured.update(params)
            captured["_url"] = url
            return {"products": []}

        self.svc._get = fake_get
        self.svc.search_cpes(**kwargs)
        return captured

    def test_default_params(self):
        params = self._call()
        assert params["resultsPerPage"] == "20"
        assert params["startIndex"] == "0"

    def test_keyword(self):
        params = self._call(keyword="apache")
        assert params["keywordSearch"] == "apache"

    def test_cpe_match_string(self):
        params = self._call(cpe_match_string="cpe:2.3:a:microsoft")
        assert params["cpeMatchString"] == "cpe:2.3:a:microsoft"

    def test_results_per_page_clamped_max(self):
        params = self._call(results_per_page=99999)
        assert params["resultsPerPage"] == "10000"

    def test_results_per_page_clamped_min(self):
        params = self._call(results_per_page=0)
        assert params["resultsPerPage"] == "1"

    def test_start_index_negative(self):
        params = self._call(start_index=-5)
        assert params["startIndex"] == "0"

    def test_calls_cpe_url(self):
        params = self._call()
        assert "cpes" in params["_url"]

    def test_none_keyword_omitted(self):
        params = self._call(keyword=None)
        assert "keywordSearch" not in params

    def test_none_cpe_match_string_omitted(self):
        params = self._call(cpe_match_string=None)
        assert "cpeMatchString" not in params


# ---------------------------------------------------------------------------
# NVDService.get_cve_history
# ---------------------------------------------------------------------------


class TestGetCveHistory:
    def setup_method(self):
        self.svc = _fresh_service()

    def _call(self, **kwargs):
        captured = {}

        def fake_get(url, params):
            captured.update(params)
            captured["_url"] = url
            return {"cveChanges": []}

        self.svc._get = fake_get
        self.svc.get_cve_history(**kwargs)
        return captured

    def test_default_params(self):
        params = self._call()
        assert params["resultsPerPage"] == "20"
        assert params["startIndex"] == "0"

    def test_cve_id(self):
        params = self._call(cve_id="CVE-2024-0001")
        assert params["cveId"] == "CVE-2024-0001"

    def test_change_start_date(self):
        params = self._call(change_start_date="2024-01-01T00:00:00.000")
        assert params["changeStartDate"] == "2024-01-01T00:00:00.000"

    def test_change_end_date(self):
        params = self._call(change_end_date="2024-03-31T23:59:59.999")
        assert params["changeEndDate"] == "2024-03-31T23:59:59.999"

    def test_event_name(self):
        params = self._call(event_name="Initial Analysis")
        assert params["eventName"] == "Initial Analysis"

    def test_results_per_page_clamped_max(self):
        params = self._call(results_per_page=99999)
        assert params["resultsPerPage"] == "5000"

    def test_results_per_page_clamped_min(self):
        params = self._call(results_per_page=0)
        assert params["resultsPerPage"] == "1"

    def test_start_index_valid(self):
        params = self._call(start_index=200)
        assert params["startIndex"] == "200"

    def test_calls_history_url(self):
        params = self._call()
        assert "cvehistory" in params["_url"]

    def test_none_optional_params_omitted(self):
        params = self._call(cve_id=None, change_start_date=None, event_name=None)
        for key in ("cveId", "changeStartDate", "eventName"):
            assert key not in params


# ---------------------------------------------------------------------------
# NVDService.get_kev
# ---------------------------------------------------------------------------


class TestGetKev:
    def setup_method(self):
        self.svc = _fresh_service()

    def _kev_payload(self) -> dict:
        return {
            "catalogVersion": "2024.05.01",
            "dateReleased": "2024-05-01T12:00:00Z",
            "vulnerabilities": [
                {"cveID": "CVE-2023-0001", "vendorProject": "Acme", "product": "Widget", "vulnerabilityName": "RCE"},
            ],
        }

    def test_success_returns_catalog(self):
        payload = self._kev_payload()
        with patch("urllib.request.urlopen", return_value=_make_response(payload)):
            result = self.svc.get_kev()
        assert result["catalogVersion"] == "2024.05.01"

    def test_retryable_error_retries_then_raises(self):
        err = _make_http_error(503)
        with patch("urllib.request.urlopen", side_effect=err), patch("time.sleep") as mock_sleep:
            with pytest.raises(urllib.error.HTTPError):
                self.svc.get_kev()
        assert mock_sleep.call_count == 2

    def test_non_retryable_error_raises_immediately(self):
        err = _make_http_error(404)
        with patch("urllib.request.urlopen", side_effect=err), patch("time.sleep") as mock_sleep:
            with pytest.raises(urllib.error.HTTPError):
                self.svc.get_kev()
        mock_sleep.assert_not_called()

    def test_url_error_retries_then_raises(self):
        err = _make_url_error("Connection refused")
        with patch("urllib.request.urlopen", side_effect=err), patch("time.sleep") as mock_sleep:
            with pytest.raises(urllib.error.URLError):
                self.svc.get_kev()
        assert mock_sleep.call_count == 2

    def test_succeeds_after_transient_error(self):
        payload = self._kev_payload()
        err = _make_http_error(503)
        with patch("urllib.request.urlopen", side_effect=[err, _make_response(payload)]), patch("time.sleep"):
            result = self.svc.get_kev()
        assert "vulnerabilities" in result

    def test_max_retries_one_no_sleep(self):
        svc = _fresh_service(NVD_HTTP_MAX_RETRIES="1")
        err = _make_http_error(429)
        with patch("urllib.request.urlopen", side_effect=err), patch("time.sleep") as mock_sleep:
            with pytest.raises(urllib.error.HTTPError):
                svc.get_kev()
        mock_sleep.assert_not_called()
