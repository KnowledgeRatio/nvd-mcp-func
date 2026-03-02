"""NVD (National Vulnerability Database) API client service."""
import json
import logging
import os
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional

_NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NVD_HISTORY_URL = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0"


class NVDService:
    """
    Client for the NVD REST APIs v2.0.

    An API key is optional but recommended — unauthenticated requests are
    limited to 5 per 30-second window; authenticated requests allow 50.
    Obtain a free key at https://nvd.nist.gov/developers/request-an-api-key
    and set it as the NVD_API_KEY environment variable.
    """

    def __init__(self) -> None:
        self._api_key: Optional[str] = os.environ.get("NVD_API_KEY") or None
        if self._api_key:
            logging.info("NVDService: authenticated mode (API key present)")
        else:
            logging.info("NVDService: unauthenticated mode (no API key — rate limited to 5 req/30s)")

    def _get(self, url: str, params: Dict[str, str]) -> Dict[str, Any]:
        """Build URL, attach auth header if available, and execute GET request."""
        query = urllib.parse.urlencode(params)
        full_url = f"{url}?{query}" if query else url

        req = urllib.request.Request(full_url)
        if self._api_key:
            req.add_header("apiKey", self._api_key)

        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode("utf-8"))

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
