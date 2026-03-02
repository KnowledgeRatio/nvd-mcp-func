import json
import logging

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
    except Exception as e:
        logging.error(f"search_cves failed: {e}")
        return json.dumps({"error": str(e)})


@app.mcp_tool()
@app.mcp_tool_property(arg_name="cve_id", description="The CVE identifier to look up (e.g. CVE-2021-44228 for Log4Shell).")
def get_cve(cve_id: str) -> str:
    """Retrieve the full details of a specific CVE by its identifier, including CVSS scores, affected configurations, references, and weakness data."""
    logging.info(f"get_cve called: cve_id={cve_id!r}")
    try:
        result = nvd_service.get_cve(cve_id)
        return json.dumps(result)
    except Exception as e:
        logging.error(f"get_cve failed: {e}")
        return json.dumps({"error": str(e)})


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
    except Exception as e:
        logging.error(f"get_cve_history failed: {e}")
        return json.dumps({"error": str(e)})
