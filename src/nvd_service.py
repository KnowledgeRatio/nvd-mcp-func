"""NVD (National Vulnerability Database) API client service."""
import json
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional

_NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NVD_HISTORY_URL = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0"
_NVD_CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
_CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class NVDService:
    """
    Client for the NVD REST APIs v2.0.

    An API key is optional but recommended - unauthenticated requests are
    limited to 5 per 30-second window; authenticated requests allow 50.
    Obtain a free key at https://nvd.nist.gov/developers/request-an-api-key
    and set it as the NVD_API_KEY environment variable.
    """

    def __init__(self) -> None:
        self._api_key: Optional[str] = os.environ.get("NVD_API_KEY") or None
        self._timeout_seconds = self._parse_positive_float(
            os.environ.get("NVD_HTTP_TIMEOUT_SECONDS"),
            default_value=15.0,
        )
        self._max_retries = self._parse_positive_int(
            os.environ.get("NVD_HTTP_MAX_RETRIES"),
            default_value=3,
        )

        if self._api_key:
            logging.info("NVDService: authenticated mode (API key present)")
        else:
            logging.info("NVDService: unauthenticated mode (no API key - rate limited to 5 req/30s)")

        logging.info(
            "NVDService: request timeout=%ss max_retries=%s",
            self._timeout_seconds,
            self._max_retries,
        )

    @staticmethod
    def _parse_positive_float(raw_value: Optional[str], default_value: float) -> float:
        if raw_value is None:
            return default_value
        try:
            parsed_value = float(raw_value)
            if parsed_value > 0:
                return parsed_value
        except ValueError:
            pass
        return default_value

    @staticmethod
    def _parse_positive_int(raw_value: Optional[str], default_value: int) -> int:
        if raw_value is None:
            return default_value
        try:
            parsed_value = int(raw_value)
            if parsed_value >= 1:
                return parsed_value
        except ValueError:
            pass
        return default_value

    @staticmethod
    def _retry_delay(attempt: int, retry_after_raw: Optional[str] = None) -> float:
        if retry_after_raw:
            try:
                retry_after = float(retry_after_raw)
                if retry_after >= 0:
                    return min(retry_after, 30.0)
            except ValueError:
                pass
        return min(0.5 * (2**attempt), 10.0)

    def _get(self, url: str, params: Dict[str, str]) -> Dict[str, Any]:
        """Build URL, attach auth header if available, and execute GET request."""
        query = urllib.parse.urlencode(params)
        full_url = f"{url}?{query}" if query else url

        for attempt in range(self._max_retries):
            req = urllib.request.Request(full_url)
            if self._api_key:
                req.add_header("apiKey", self._api_key)

            try:
                with urllib.request.urlopen(req, timeout=self._timeout_seconds) as response:
                    return json.loads(response.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                is_last_attempt = attempt >= self._max_retries - 1
                is_retryable = exc.code in {429, 500, 502, 503, 504}
                if is_last_attempt or not is_retryable:
                    raise
                retry_after_raw = exc.headers.get("Retry-After") if exc.headers else None
                delay = self._retry_delay(attempt, retry_after_raw)
                logging.warning(
                    "NVDService._get transient HTTP %s. retry=%s/%s delay=%ss",
                    exc.code,
                    attempt + 1,
                    self._max_retries,
                    delay,
                )
                time.sleep(delay)
            except urllib.error.URLError as exc:
                if attempt >= self._max_retries - 1:
                    raise
                delay = self._retry_delay(attempt)
                logging.warning(
                    "NVDService._get transient network error %r. retry=%s/%s delay=%ss",
                    exc.reason,
                    attempt + 1,
                    self._max_retries,
                    delay,
                )
                time.sleep(delay)

        raise RuntimeError("NVDService._get exhausted retries unexpectedly")

    def search_cves(
        self,
        keyword: Optional[str] = None,
        cve_id: Optional[str] = None,
        cpe_name: Optional[str] = None,
        cvss_v3_severity: Optional[str] = None,
        cwe_id: Optional[str] = None,
        pub_start_date: Optional[str] = None,
        pub_end_date: Optional[str] = None,
        last_mod_start_date: Optional[str] = None,
        last_mod_end_date: Optional[str] = None,
        has_kev: bool = False,
        results_per_page: int = 20,
        start_index: int = 0,
    ) -> Dict[str, Any]:
        """
        Search the NVD CVE database.

        Date parameters must use ISO 8601 format: 2024-01-01T00:00:00.000
        Date ranges are limited to 120 days by the NVD API.
        """
        params: Dict[str, str] = {}

        if keyword:
            params["keywordSearch"] = keyword
        if cve_id:
            params["cveId"] = cve_id
        if cpe_name:
            params["cpeName"] = cpe_name
        if cvss_v3_severity:
            params["cvssV3Severity"] = cvss_v3_severity.upper()
        if cwe_id:
            params["cweId"] = cwe_id
        if pub_start_date:
            params["pubStartDate"] = pub_start_date
        if pub_end_date:
            params["pubEndDate"] = pub_end_date
        if last_mod_start_date:
            params["lastModStartDate"] = last_mod_start_date
        if last_mod_end_date:
            params["lastModEndDate"] = last_mod_end_date
        if has_kev:
            params["hasKev"] = ""

        params["resultsPerPage"] = str(min(max(1, results_per_page), 2000))
        params["startIndex"] = str(max(0, start_index))

        logging.info(f"NVDService.search_cves: params={params}")
        return self._get(_NVD_CVE_URL, params)

    def get_cve(self, cve_id: str) -> Dict[str, Any]:
        """Fetch a single CVE record by its identifier."""
        logging.info(f"NVDService.get_cve: cveId={cve_id}")
        return self._get(_NVD_CVE_URL, {"cveId": cve_id})

    def search_cpes(
        self,
        keyword: Optional[str] = None,
        cpe_match_string: Optional[str] = None,
        results_per_page: int = 20,
        start_index: int = 0,
    ) -> Dict[str, Any]:
        """Search the NVD CPE dictionary for product entries."""
        params: Dict[str, str] = {}

        if keyword:
            params["keywordSearch"] = keyword
        if cpe_match_string:
            params["cpeMatchString"] = cpe_match_string

        params["resultsPerPage"] = str(min(max(1, results_per_page), 10000))
        params["startIndex"] = str(max(0, start_index))

        logging.info(f"NVDService.search_cpes: params={params}")
        return self._get(_NVD_CPE_URL, params)

    def get_kev(self) -> Dict[str, Any]:
        """Fetch the CISA Known Exploited Vulnerabilities catalog."""
        logging.info("NVDService.get_kev: fetching CISA KEV catalog")

        for attempt in range(self._max_retries):
            req = urllib.request.Request(_CISA_KEV_URL)
            try:
                with urllib.request.urlopen(req, timeout=self._timeout_seconds) as response:
                    return json.loads(response.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                is_last_attempt = attempt >= self._max_retries - 1
                is_retryable = exc.code in {429, 500, 502, 503, 504}
                if is_last_attempt or not is_retryable:
                    raise
                delay = self._retry_delay(attempt)
                logging.warning(
                    "NVDService.get_kev transient HTTP %s. retry=%s/%s delay=%ss",
                    exc.code, attempt + 1, self._max_retries, delay,
                )
                time.sleep(delay)
            except urllib.error.URLError as exc:
                if attempt >= self._max_retries - 1:
                    raise
                delay = self._retry_delay(attempt)
                logging.warning(
                    "NVDService.get_kev transient network error %r. retry=%s/%s delay=%ss",
                    exc.reason, attempt + 1, self._max_retries, delay,
                )
                time.sleep(delay)

        raise RuntimeError("NVDService.get_kev exhausted retries unexpectedly")

    def get_cve_history(
        self,
        cve_id: Optional[str] = None,
        change_start_date: Optional[str] = None,
        change_end_date: Optional[str] = None,
        event_name: Optional[str] = None,
        results_per_page: int = 20,
        start_index: int = 0,
    ) -> Dict[str, Any]:
        """
        Retrieve the change history for CVE records.

        Date parameters must use ISO 8601 format: 2024-01-01T00:00:00.000
        Date ranges are limited to 120 days by the NVD API.
        """
        params: Dict[str, str] = {}

        if cve_id:
            params["cveId"] = cve_id
        if change_start_date:
            params["changeStartDate"] = change_start_date
        if change_end_date:
            params["changeEndDate"] = change_end_date
        if event_name:
            params["eventName"] = event_name

        params["resultsPerPage"] = str(min(max(1, results_per_page), 5000))
        params["startIndex"] = str(max(0, start_index))

        logging.info(f"NVDService.get_cve_history: params={params}")
        return self._get(_NVD_HISTORY_URL, params)
