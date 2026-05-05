import datetime
import json
import logging
import urllib.error

import azure.functions as func
from nvd_service import NVDService

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

nvd_service = NVDService()


@app.mcp_tool()
@app.mcp_tool_property(arg_name="keyword", description="Keywords to search within CVE descriptions and titles (e.g. 'log4j', 'remote code execution').", is_required=False)
@app.mcp_tool_property(arg_name="cve_id", description="A specific CVE identifier to retrieve (e.g. CVE-2021-44228). When provided, other filters are ignored.", is_required=False)
@app.mcp_tool_property(arg_name="cpe_name", description="CPE 2.3 name to filter CVEs associated with a specific product (e.g. cpe:2.3:a:apache:log4j:*).", is_required=False)
@app.mcp_tool_property(arg_name="cvss_v3_severity", description="Filter by CVSS v3 severity level: LOW, MEDIUM, HIGH, or CRITICAL.", is_required=False)
@app.mcp_tool_property(arg_name="cwe_id", description="Filter by Common Weakness Enumeration identifier (e.g. CWE-79 for XSS).", is_required=False)
@app.mcp_tool_property(arg_name="pub_start_date", description="Filter by publication start date in ISO 8601 format (e.g. 2024-01-01T00:00:00.000). Maximum range is 120 days.", is_required=False)
@app.mcp_tool_property(arg_name="pub_end_date", description="Filter by publication end date in ISO 8601 format (e.g. 2024-03-31T23:59:59.999). Maximum range is 120 days.", is_required=False)
@app.mcp_tool_property(arg_name="last_mod_start_date", description="Filter by last-modified start date in ISO 8601 format. Maximum range is 120 days.", is_required=False)
@app.mcp_tool_property(arg_name="last_mod_end_date", description="Filter by last-modified end date in ISO 8601 format. Maximum range is 120 days.", is_required=False)
@app.mcp_tool_property(arg_name="has_kev", description="When true, return only CVEs that appear in the CISA Known Exploited Vulnerabilities (KEV) catalog.", is_required=False)
@app.mcp_tool_property(arg_name="results_per_page", description="Number of results to return per page (1–2000). Defaults to 20.", is_required=False)
@app.mcp_tool_property(arg_name="start_index", description="Zero-based index of the first result to return, used for pagination. Defaults to 0.", is_required=False)
def search_cves(
    keyword: str = "",
    cve_id: str = "",
    cpe_name: str = "",
    cvss_v3_severity: str = "",
    cwe_id: str = "",
    pub_start_date: str = "",
    pub_end_date: str = "",
    last_mod_start_date: str = "",
    last_mod_end_date: str = "",
    has_kev: bool = False,
    results_per_page: int = 20,
    start_index: int = 0,
) -> str:
    """Search the NVD CVE database with optional filters. Returns matching vulnerabilities with CVSS scores, descriptions, and metadata."""
    logging.info(f"search_cves called: keyword={keyword!r} cve_id={cve_id!r} severity={cvss_v3_severity!r}")
    try:
        result = nvd_service.search_cves(
            keyword=keyword or None,
            cve_id=cve_id or None,
            cpe_name=cpe_name or None,
            cvss_v3_severity=cvss_v3_severity or None,
            cwe_id=cwe_id or None,
            pub_start_date=pub_start_date or None,
            pub_end_date=pub_end_date or None,
            last_mod_start_date=last_mod_start_date or None,
            last_mod_end_date=last_mod_end_date or None,
            has_kev=has_kev,
            results_per_page=results_per_page,
            start_index=start_index,
        )
        return json.dumps(result)
    except urllib.error.HTTPError as e:
        logging.error(f"search_cves NVD API error: {e.code} {e.reason}")
        return json.dumps({"error": "CVE database request failed", "status": e.code})
    except urllib.error.URLError as e:
        logging.error(f"search_cves NVD API unreachable: {e.reason}")
        return json.dumps({"error": "CVE database unreachable"})
    except Exception as e:
        logging.exception("search_cves unexpected error")
        return json.dumps({"error": "Internal error"})


@app.mcp_tool()
@app.mcp_tool_property(arg_name="cve_id", description="The CVE identifier to look up (e.g. CVE-2021-44228 for Log4Shell).")
def get_cve(cve_id: str) -> str:
    """Retrieve the full details of a specific CVE by its identifier, including CVSS scores, affected configurations, references, and weakness data."""
    logging.info(f"get_cve called: cve_id={cve_id!r}")
    try:
        result = nvd_service.get_cve(cve_id)
        return json.dumps(result)
    except urllib.error.HTTPError as e:
        logging.error(f"get_cve NVD API error: {e.code} {e.reason}")
        return json.dumps({"error": "CVE database request failed", "status": e.code})
    except urllib.error.URLError as e:
        logging.error(f"get_cve NVD API unreachable: {e.reason}")
        return json.dumps({"error": "CVE database unreachable"})
    except Exception as e:
        logging.exception("get_cve unexpected error")
        return json.dumps({"error": "Internal error"})


@app.mcp_tool()
@app.mcp_tool_property(arg_name="cve_id", description="Retrieve change history for a specific CVE identifier (e.g. CVE-2021-44228). Leave empty to query by date range instead.", is_required=False)
@app.mcp_tool_property(arg_name="change_start_date", description="Start of the change event date range in ISO 8601 format (e.g. 2024-01-01T00:00:00.000). Maximum range is 120 days.", is_required=False)
@app.mcp_tool_property(arg_name="change_end_date", description="End of the change event date range in ISO 8601 format (e.g. 2024-03-31T23:59:59.999). Maximum range is 120 days.", is_required=False)
@app.mcp_tool_property(arg_name="event_name", description="Filter by event type, e.g. 'Initial Analysis', 'Reanalysis', 'CVE Modified', 'CVE Rejected', 'CVE Translated'.", is_required=False)
@app.mcp_tool_property(arg_name="results_per_page", description="Number of results to return per page (1–5000). Defaults to 20.", is_required=False)
@app.mcp_tool_property(arg_name="start_index", description="Zero-based index of the first result to return, used for pagination. Defaults to 0.", is_required=False)
def get_cve_history(
    cve_id: str = "",
    change_start_date: str = "",
    change_end_date: str = "",
    event_name: str = "",
    results_per_page: int = 20,
    start_index: int = 0,
) -> str:
    """Retrieve the change history for CVE records, showing how vulnerabilities have been updated over time."""
    logging.info(f"get_cve_history called: cve_id={cve_id!r} event={event_name!r}")
    try:
        result = nvd_service.get_cve_history(
            cve_id=cve_id or None,
            change_start_date=change_start_date or None,
            change_end_date=change_end_date or None,
            event_name=event_name or None,
            results_per_page=results_per_page,
            start_index=start_index,
        )
        return json.dumps(result)
    except urllib.error.HTTPError as e:
        logging.error(f"get_cve_history NVD API error: {e.code} {e.reason}")
        return json.dumps({"error": "CVE database request failed", "status": e.code})
    except urllib.error.URLError as e:
        logging.error(f"get_cve_history NVD API unreachable: {e.reason}")
        return json.dumps({"error": "CVE database unreachable"})
    except Exception as e:
        logging.exception("get_cve_history unexpected error")
        return json.dumps({"error": "Internal error"})


@app.mcp_tool()
@app.mcp_tool_property(arg_name="cpe_name", description="CPE 2.3 name to filter CVEs associated with a specific product (e.g. cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*).")
@app.mcp_tool_property(arg_name="results_per_page", description="Number of results to return per page (1–2000). Defaults to 20.", is_required=False)
@app.mcp_tool_property(arg_name="start_index", description="Zero-based index of the first result to return, used for pagination. Defaults to 0.", is_required=False)
def search_cves_by_cpe(
    cpe_name: str,
    results_per_page: int = 20,
    start_index: int = 0,
) -> str:
    """Find all CVEs that affect a specific product using its CPE 2.3 name. Use search_cpes first to find the exact CPE URI."""
    logging.info(f"search_cves_by_cpe called: cpe_name={cpe_name!r}")
    try:
        result = nvd_service.search_cves(
            cpe_name=cpe_name,
            results_per_page=results_per_page,
            start_index=start_index,
        )
        return json.dumps(result)
    except urllib.error.HTTPError as e:
        logging.error(f"search_cves_by_cpe NVD API error: {e.code} {e.reason}")
        return json.dumps({"error": "CVE database request failed", "status": e.code})
    except urllib.error.URLError as e:
        logging.error(f"search_cves_by_cpe NVD API unreachable: {e.reason}")
        return json.dumps({"error": "CVE database unreachable"})
    except Exception as e:
        logging.exception("search_cves_by_cpe unexpected error")
        return json.dumps({"error": "Internal error"})


@app.mcp_tool()
@app.mcp_tool_property(arg_name="days", description="How many days back to look (default 7, max 120).", is_required=False)
@app.mcp_tool_property(arg_name="cvss_v3_severity", description="Filter by CVSS v3 severity level: LOW, MEDIUM, HIGH, or CRITICAL.", is_required=False)
@app.mcp_tool_property(arg_name="has_kev", description="When true, return only CVEs that appear in the CISA Known Exploited Vulnerabilities (KEV) catalog.", is_required=False)
@app.mcp_tool_property(arg_name="results_per_page", description="Number of results to return per page (1–2000). Defaults to 20.", is_required=False)
@app.mcp_tool_property(arg_name="start_index", description="Zero-based index of the first result to return, used for pagination. Defaults to 0.", is_required=False)
def get_recent_cves(
    days: int = 7,
    cvss_v3_severity: str = "",
    has_kev: bool = False,
    results_per_page: int = 20,
    start_index: int = 0,
) -> str:
    """Get CVEs published in the last N days, optionally filtered by severity or CISA KEV status."""
    logging.info(f"get_recent_cves called: days={days} severity={cvss_v3_severity!r} has_kev={has_kev}")
    try:
        now = datetime.datetime.now(datetime.timezone.utc)
        past = now - datetime.timedelta(days=max(1, min(days, 120)))
        fmt = lambda d: d.strftime("%Y-%m-%dT%H:%M:%S.000")
        result = nvd_service.search_cves(
            pub_start_date=fmt(past),
            pub_end_date=fmt(now),
            cvss_v3_severity=cvss_v3_severity or None,
            has_kev=has_kev,
            results_per_page=results_per_page,
            start_index=start_index,
        )
        return json.dumps(result)
    except urllib.error.HTTPError as e:
        logging.error(f"get_recent_cves NVD API error: {e.code} {e.reason}")
        return json.dumps({"error": "CVE database request failed", "status": e.code})
    except urllib.error.URLError as e:
        logging.error(f"get_recent_cves NVD API unreachable: {e.reason}")
        return json.dumps({"error": "CVE database unreachable"})
    except Exception as e:
        logging.exception("get_recent_cves unexpected error")
        return json.dumps({"error": "Internal error"})


@app.mcp_tool()
@app.mcp_tool_property(arg_name="keyword", description="Product name or vendor keyword to search for (e.g. 'apache tomcat' or 'openssl').", is_required=False)
@app.mcp_tool_property(arg_name="cpe_match_string", description="Partial CPE 2.3 string to match against (e.g. cpe:2.3:a:microsoft).", is_required=False)
@app.mcp_tool_property(arg_name="results_per_page", description="Number of results to return per page (1–10000). Defaults to 20.", is_required=False)
@app.mcp_tool_property(arg_name="start_index", description="Zero-based index of the first result to return, used for pagination. Defaults to 0.", is_required=False)
def search_cpes(
    keyword: str = "",
    cpe_match_string: str = "",
    results_per_page: int = 20,
    start_index: int = 0,
) -> str:
    """Search for CPE product entries by name or keyword. Use this to find the exact CPE URI needed for search_cves_by_cpe or the cpe_name filter in search_cves."""
    logging.info(f"search_cpes called: keyword={keyword!r} cpe_match_string={cpe_match_string!r}")
    try:
        result = nvd_service.search_cpes(
            keyword=keyword or None,
            cpe_match_string=cpe_match_string or None,
            results_per_page=results_per_page,
            start_index=start_index,
        )
        return json.dumps(result)
    except urllib.error.HTTPError as e:
        logging.error(f"search_cpes NVD API error: {e.code} {e.reason}")
        return json.dumps({"error": "CPE database request failed", "status": e.code})
    except urllib.error.URLError as e:
        logging.error(f"search_cpes NVD API unreachable: {e.reason}")
        return json.dumps({"error": "CPE database unreachable"})
    except Exception as e:
        logging.exception("search_cpes unexpected error")
        return json.dumps({"error": "Internal error"})


@app.mcp_tool()
@app.mcp_tool_property(arg_name="keyword", description="Filter by vendor, product, or vulnerability name (case-insensitive).", is_required=False)
@app.mcp_tool_property(arg_name="since", description="Only return entries added to KEV on or after this date (YYYY-MM-DD).", is_required=False)
@app.mcp_tool_property(arg_name="ransomware_only", description="When true, only return entries with a known ransomware campaign association.", is_required=False)
@app.mcp_tool_property(arg_name="results_per_page", description="Maximum number of entries to return (1–2000). Defaults to 10.", is_required=False)
def get_kev(
    keyword: str = "",
    since: str = "",
    ransomware_only: bool = False,
    results_per_page: int = 10,
) -> str:
    """Fetch the CISA Known Exploited Vulnerabilities (KEV) catalog live. Returns catalog summary and most recent entries. Filter by keyword, date, or ransomware association."""
    logging.info(f"get_kev called: keyword={keyword!r} since={since!r} ransomware_only={ransomware_only}")
    try:
        catalog = nvd_service.get_kev()
        vulns = catalog.get("vulnerabilities", [])

        if since:
            vulns = [v for v in vulns if v.get("dateAdded", "") >= since]
        if ransomware_only:
            vulns = [v for v in vulns if v.get("knownRansomwareCampaignUse") == "Known"]
        if keyword:
            kw = keyword.lower()
            vulns = [
                v for v in vulns
                if kw in (v.get("vendorProject") or "").lower()
                or kw in (v.get("product") or "").lower()
                or kw in (v.get("vulnerabilityName") or "").lower()
                or kw in (v.get("cveID") or "").lower()
            ]

        limit = min(max(1, results_per_page), 2000)
        sorted_vulns = sorted(vulns, key=lambda v: v.get("dateAdded", ""), reverse=True)
        page = sorted_vulns[:limit]
        ransomware_count = sum(1 for v in vulns if v.get("knownRansomwareCampaignUse") == "Known")

        return json.dumps({
            "catalogVersion": catalog.get("catalogVersion"),
            "dateReleased": catalog.get("dateReleased"),
            "matched": len(vulns),
            "ransomwareAssociated": ransomware_count,
            "showing": len(page),
            "vulnerabilities": page,
        })
    except urllib.error.HTTPError as e:
        logging.error(f"get_kev CISA fetch error: {e.code} {e.reason}")
        return json.dumps({"error": "CISA KEV catalog request failed", "status": e.code})
    except urllib.error.URLError as e:
        logging.error(f"get_kev CISA unreachable: {e.reason}")
        return json.dumps({"error": "CISA KEV catalog unreachable"})
    except Exception as e:
        logging.exception("get_kev unexpected error")
        return json.dumps({"error": "Internal error"})
