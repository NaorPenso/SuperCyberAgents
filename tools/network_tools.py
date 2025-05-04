"""Network security tools for the NetworkSecurityAgent.

This module provides tools for network security scanning and analysis, primarily
using Nuclei from ProjectDiscovery to scan networks, endpoints, and servers for
vulnerabilities.
"""

import asyncio
import json
import logging
import os
import subprocess
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field
from pydantic_ai.tools import RunContext, Tool


class NucleiScanParams(BaseModel):
    """Parameters for nuclei_scan_tool, aiming for parity with nuclei flags."""

    # Target Specification
    target: str = Field(..., description="Target URL/host to scan (-target, -u)")
    # list: Optional[str] = Field(
    #    None, description="Path to file list (-l, -list)" # Requires file handling
    # )
    exclude_hosts: Optional[List[str]] = Field(
        default=None,
        description="Hosts to exclude (ip, cidr, hostname) (-eh, -exclude-hosts)",
    )
    # resume: Optional[str] = Field(
    #     None, description="Resume scan using resume.cfg (-resume)" # State management
    # )
    scan_all_ips: bool = Field(
        default=False,
        description="Scan all IPs associated with DNS record (-sa, -scan-all-ips)",
    )
    ip_version: Optional[List[str]] = Field(
        default=None, description="IP version(s) to scan (4, 6) (-iv, -ip-version)"
    )

    # Template Selection / Filtering
    new_templates: bool = Field(
        default=False,
        description="Run only new templates added in latest release (-nt, -new-templates)",  # noqa: E501
    )
    new_templates_version: Optional[List[str]] = Field(
        default=None,
        description=(
            "Run new templates added in specific versions "
            "(-ntv, -new-templates-version)"
        ),
    )
    automatic_scan: bool = Field(
        default=False,
        description="Automatic web scan using wappalyzer tags (-as, -automatic-scan)",
    )
    templates: Optional[List[str]] = Field(
        default=None, description="Templates/directories to run (-t, -templates)"
    )
    template_url: Optional[List[str]] = Field(
        default=None, description="Template URLs to run (-turl, -template-url)"
    )
    workflows: Optional[List[str]] = Field(
        default=None, description="Workflows/directories to run (-w, -workflows)"
    )
    workflow_url: Optional[List[str]] = Field(
        default=None, description="Workflow URLs to run (-wurl, -workflow-url)"
    )
    validate_templates: bool = Field(
        default=False, description="Validate the specified templates (-validate)"
    )
    no_strict_syntax: bool = Field(
        default=False,
        description="Disable strict template syntax check (-nss, -no-strict-syntax)",
    )
    # template_display: bool = Field(
    #     False, description="Display template content (-td)" # Informational
    # )
    # code: bool = Field(
    #     False, description="Enable loading code protocol templates (-code)"
    #     # Requires security considerations
    # )
    # disable_unsigned_templates: bool = Field(
    #     False, description="Disable unsigned templates (-dut)"
    # )

    # Filtering (Authors, Tags, Severity, ID, Type, Conditions)
    author: Optional[List[str]] = Field(
        default=None, description="Filter templates by author (-a, -author)"
    )
    tags: Optional[List[str]] = Field(
        default=None, description="Filter templates by tags (-tags)"
    )
    exclude_tags: Optional[List[str]] = Field(
        default=None, description="Exclude templates by tags (-etags, -exclude-tags)"
    )
    include_tags: Optional[List[str]] = Field(
        default=None,
        description="Tags to include even if excluded (-itags, -include-tags)",
    )
    template_id: Optional[List[str]] = Field(
        default=None,
        description="Filter templates by ID (allow-wildcard) (-id, -template-id)",
    )
    exclude_id: Optional[List[str]] = Field(
        default=None, description="Exclude templates by ID (-eid, -exclude-id)"
    )
    include_templates: Optional[List[str]] = Field(
        default=None,
        description="Templates to include even if excluded (-it, -include-templates)",
    )
    exclude_templates: Optional[List[str]] = Field(
        default=None,
        description="Templates/directories to exclude (-et, -exclude-templates)",
    )
    exclude_matchers: Optional[List[str]] = Field(
        default=None,
        description=(
            "Template matchers to exclude from results " "(-em, -exclude-matchers)"
        ),
    )
    severity: Optional[List[str]] = Field(
        default=None,
        description=(
            "Filter by severity (info, low, medium, high, critical, unknown) "
            "(-s, -severity)"
        ),
    )
    exclude_severity: Optional[List[str]] = Field(
        default=None, description="Exclude by severity (-es, -exclude-severity)"
    )
    protocol_type: Optional[List[str]] = Field(
        default=None,
        description="Filter by protocol type (dns, http, tcp, etc.) (-pt, -type)",
    )
    exclude_type: Optional[List[str]] = Field(
        default=None, description="Exclude by protocol type (-ept, -exclude-type)"
    )
    template_condition: Optional[List[str]] = Field(
        default=None,
        description=(
            "Filter templates based on expression condition "
            "(-tc, -template-condition)"
        ),
    )

    # Output Configuration (subset)
    store_resp: bool = Field(
        default=False,
        description="Store all request/response pairs (-sresp, -store-resp)",
    )
    store_resp_dir: Optional[str] = Field(
        default=None,
        description=(
            "Directory to store request/response pairs " "(-srd, -store-resp-dir)"
        ),
    )
    omit_raw: bool = Field(
        default=False,
        description=(
            "Omit request/response pairs from JSON/JSONL output " "(-or, -omit-raw)"
        ),
    )
    omit_template: bool = Field(
        default=False,
        description=(
            "Omit encoded template from JSON/JSONL output " "(-ot, -omit-template)"
        ),
    )
    matcher_status: bool = Field(
        default=False, description="Display match failure status (-ms, -matcher-status)"
    )
    # report_db: Optional[str] = Field(
    #     None, description="Reporting database path (-rdb)" # State
    # )
    # markdown_export: Optional[str] = Field(
    #     None, description="Markdown export directory (-me)" # File I/O
    # )
    # sarif_export: Optional[str] = Field(
    #     None, description="SARIF export file (-se)" # File I/O
    # )
    # json_export: Optional[str] = Field(
    #     None, description="JSON export file (-je)" # File I/O
    # )
    # jsonl_export: Optional[str] = Field(
    #     None, description="JSONL export file (-jle)" # File I/O
    # )
    redact_keys: Optional[List[str]] = Field(
        default=None, description="List of keys to redact from output (-rd, -redact)"
    )

    # General Configuration
    follow_redirects: bool = Field(
        default=False,
        description="Enable following HTTP redirects (-fr, -follow-redirects)",
    )
    follow_host_redirects: bool = Field(
        default=False,
        description=(
            "Follow redirects only on the same host " "(-fhr, -follow-host-redirects)"
        ),
    )
    max_redirects: Optional[int] = Field(
        default=None,
        description="Max number of redirects to follow (-mr, -max-redirects)",
    )
    disable_redirects: bool = Field(
        default=False, description="Disable HTTP redirects (-dr, -disable-redirects)"
    )
    # report_config: Optional[str] = Field(
    #     None, description="Path to reporting config file (-rc)"
    # )
    header: Optional[List[str]] = Field(
        default=None, description="Custom headers (header:value format) (-H, -header)"
    )
    # vars: Optional[Dict[str, str]] = Field(
    #     None, description="Custom variables (key=value format) (-V, -var)"
    #     # Needs parsing
    # )
    system_resolvers: bool = Field(
        default=False,
        description="Use system DNS resolving as error fallback (-sr, -system-resolvers)",  # noqa: E501
    )
    disable_clustering: bool = Field(
        default=False,
        description="Disable request clustering (-dc, -disable-clustering)",
    )
    passive: bool = Field(
        default=False, description="Enable passive HTTP response processing (-passive)"
    )
    force_http2: bool = Field(
        default=False, description="Force HTTP/2 connections (-fh2, -force-http2)"
    )
    env_vars: bool = Field(
        default=False,
        description="Enable environment variables in templates (-ev, -env-vars)",
    )
    # client_cert / client_key / client_ca: Optional[str] = Field(
    #     None, ... # File paths
    # )
    # show_match_line: bool = Field(
    #     False, description="Show match lines for file templates (-sml)"
    # )
    # tls_impersonate: bool = Field(
    #     False, description="Enable JA3 TLS randomization (-tlsi)"
    # )
    # dialer_keep_alive: Optional[str] = Field(
    #     None, description="Keep-alive duration (-dka)"
    # )
    # allow_local_file_access: bool = Field(
    #     False, description="Allow local file access (-lfa)" # Security risk
    # )
    restrict_local_network_access: bool = Field(
        default=False,
        description=(
            "Block connections to local/private network "
            "(-lna, -restrict-local-network-access)"
        ),
    )
    interface: Optional[str] = Field(
        default=None,
        description="Network interface to use for scanning (-i, -interface)",
    )
    attack_type: Optional[str] = Field(
        default=None,
        description=(
            "Payload combination attack type (batteringram, pitchfork, clusterbomb) "
            "(-at, -attack-type)"
        ),
    )
    source_ip: Optional[str] = Field(
        default=None, description="Source IP address for scanning (-sip, -source-ip)"
    )
    response_size_read: Optional[int] = Field(
        default=None,
        description="Max response size to read in bytes (-rsr, -response-size-read)",
    )
    # response_size_save: Optional[int] = Field(None, ...) # Default handled by nuclei

    # Interactsh
    interactsh_server: Optional[str] = Field(
        default=None,
        description=(
            "Interactsh server URL for self-hosted instance "
            "(-iserver, -interactsh-server)"
        ),
    )
    interactsh_token: Optional[str] = Field(
        default=None,
        description=(
            "Authentication token for self-hosted Interactsh "
            "(-itoken, -interactsh-token)"
        ),
    )
    interactions_cache_size: Optional[int] = Field(
        default=None,
        description=(
            "Number of requests to keep in interactions cache "
            "(-interactions-cache-size)"
        ),
    )
    interactions_eviction: Optional[int] = Field(
        default=None,
        description=(
            "Seconds before evicting requests from cache " "(-interactions-eviction)"
        ),
    )
    interactions_poll_duration: Optional[int] = Field(
        default=None,
        description=(
            "Seconds between interaction poll requests " "(-interactions-poll-duration)"
        ),
    )
    interactions_cooldown_period: Optional[int] = Field(
        default=None,
        description=(
            "Extra time for polling before exiting " "(-interactions-cooldown-period)"
        ),
    )
    no_interactsh: bool = Field(
        default=False, description="Disable Interactsh OAST tests (-ni, -no-interactsh)"
    )

    # Fuzzing (subset)
    fuzzing_type: Optional[str] = Field(
        default=None,
        description=(
            "Override fuzzing type (replace, prefix, postfix, infix) "
            "(-ft, -fuzzing-type)"
        ),
    )
    fuzzing_mode: Optional[str] = Field(
        default=None,
        description=(
            "Override fuzzing mode (multiple, single) " "(-fm, -fuzzing-mode)"
        ),
    )
    dast: bool = Field(
        default=False, description="Enable/run DAST (fuzzing) templates (-dast)"
    )
    # Other fuzzing flags omitted for brevity / complexity

    # Uncover (subset)
    uncover: bool = Field(
        default=False, description="Enable Uncover engine integration (-uc, -uncover)"
    )
    uncover_query: Optional[List[str]] = Field(
        default=None, description="Uncover search query (-uq, -uncover-query)"
    )
    uncover_engine: Optional[List[str]] = Field(
        default=None,
        description="Uncover search engine(s) to use (-ue, -uncover-engine)",
    )
    uncover_field: Optional[str] = Field(
        default=None,
        description="Uncover fields to return (ip, port, host) (-uf, -uncover-field)",
    )
    uncover_limit: Optional[int] = Field(
        default=None, description="Number of results for Uncover (-ul, -uncover-limit)"
    )

    # Rate Limit (Detailed)
    rate_limit: int = Field(
        default=150, description="Max requests per second (-rl, -rate-limit)"
    )
    # rate_limit_duration: Optional[str] = Field(
    #     None, description="Duration for rate limit (e.g., 1s, 1m) (-rld)"
    # )
    # rate_limit_minute: Optional[int] = Field(
    #     None, description="Max requests per minute (-rlm, DEPRECATED)"
    # )
    bulk_size: Optional[int] = Field(
        default=None, description="Max hosts per template in parallel (-bs, -bulk-size)"
    )
    concurrency: Optional[int] = Field(
        default=None, description="Max templates in parallel (-c, -concurrency)"
    )
    headless_bulk_size: Optional[int] = Field(
        default=None,
        description="Max headless hosts per template (-hbs, -headless-bulk-size)",
    )
    headless_concurrency: Optional[int] = Field(
        default=None,
        description=(
            "Max headless templates in parallel " "(-headc, -headless-concurrency)"
        ),
    )
    payload_concurrency: Optional[int] = Field(
        default=None,
        description=(
            "Max payload concurrency per template " "(-pc, -payload-concurrency)"
        ),
    )
    probe_concurrency: Optional[int] = Field(
        default=None,
        description="HTTP probe concurrency with httpx (-prc, -probe-concurrency)",
    )

    # Optimizations
    timeout: int = Field(
        default=10,
        description="Timeout in seconds before cancelling request (-timeout)",
    )
    retries: Optional[int] = Field(
        default=None, description="Number of times to retry a failed request (-retries)"
    )
    leave_default_ports: bool = Field(
        default=False,
        description=(
            "Leave default HTTP/HTTPS ports (host:80, host:443) "
            "(-ldp, -leave-default-ports)"
        ),
    )
    max_host_error: Optional[int] = Field(
        default=None,
        description="Max errors for a host before skipping (-mhe, -max-host-error)",
    )
    track_error: Optional[List[str]] = Field(
        default=None,
        description=(
            "Add error strings to max-host-error watchlist " "(-te, -track-error)"
        ),
    )
    no_mhe: bool = Field(
        default=False,
        description="Disable skipping host based on errors (-nmhe, -no-mhe)",
    )
    project: bool = Field(
        default=False,
        description=(
            "Use project folder to avoid sending same request multiple times "
            "(-project)"
        ),
    )
    project_path: Optional[str] = Field(
        default=None, description="Specific project path (-project-path)"
    )
    stop_at_first_match: bool = Field(
        default=False,
        description=(
            "Stop processing HTTP requests after first match "
            "(-spm, -stop-at-first-match)"
        ),
    )
    stream: bool = Field(
        default=False,
        description="Stream mode - process input without sorting (-stream)",
    )
    scan_strategy: Optional[str] = Field(
        default=None,
        description=(
            "Scan strategy (auto, host-spray, template-spray) " "(-ss, -scan-strategy)"
        ),
    )
    input_read_timeout: Optional[str] = Field(
        default=None,
        description="Timeout on input read (e.g., 3m0s) (-irt, -input-read-timeout)",
    )
    no_httpx: bool = Field(
        default=False,
        description="Disable httpx probing for non-URL input (-nh, -no-httpx)",
    )
    no_stdin: bool = Field(
        default=False, description="Disable stdin processing (-no-stdin)"
    )

    # Headless (subset)
    headless: bool = Field(
        default=False, description="Enable headless browser templates (-headless)"
    )
    page_timeout: Optional[int] = Field(
        default=None,
        description="Seconds to wait for each page in headless mode (-page-timeout)",
    )
    show_browser: bool = Field(
        default=False,
        description="Show browser screen during headless scans (-sb, -show-browser)",
    )
    # headless_options: Optional[List[str]] = Field(
    #     None, description="Additional chrome options (-ho)"
    # )
    system_chrome: bool = Field(
        default=False,
        description="Use local installed Chrome browser (-sc, -system-chrome)",
    )

    # Debugging
    debug: bool = Field(
        default=False, description="Show all requests and responses (-debug)"
    )
    debug_req: bool = Field(
        default=False, description="Show all sent requests (-dreq, -debug-req)"
    )
    debug_resp: bool = Field(
        default=False, description="Show all received responses (-dresp, -debug-resp)"
    )
    proxy: Optional[List[str]] = Field(  # Changed to list to match flag usage
        default=None, description="HTTP/SOCKS5 proxy URLs (-p, -proxy)"
    )
    proxy_internal: bool = Field(
        default=False, description="Proxy all internal requests (-pi, -proxy-internal)"
    )
    # trace_log: Optional[str] = Field(
    #     None, description="File for request trace log (-tlog)"
    # )
    # error_log: Optional[str] = Field(
    #     None, description="File for request error log (-elog)"
    # )
    hang_monitor: bool = Field(
        default=False, description="Enable nuclei hang monitoring (-hm, -hang-monitor)"
    )
    verbose: bool = Field(default=False, description="Show verbose output (-v)")
    show_var_dump: bool = Field(
        default=False,
        description="Show variables dump for debugging (-svd, -show-var-dump)",
    )
    var_dump_limit: Optional[int] = Field(
        default=None,
        description="Limit the number of variables shown in the dump (-vdl, -var-dump-limit)",  # noqa: E501
    )
    # metrics: bool = Field(
    #     False, description="Expose metrics on a port (-metrics)"
    # )
    # metrics_port: Optional[int] = Field(
    #     None, description="Port for exposing metrics (-metrics-port)"
    # )
    # output_response: bool = Field(
    #     False, description="Output matched HTTP response (-or, DEPRECATED)"
    #     # Handled by store_resp
    # )


class NucleiResult(BaseModel):
    """Result from a nuclei scan."""

    scan_status: Literal["success_with_findings", "success_no_findings", "error"] = (
        Field(..., description="Explicit status of the scan outcome.")
    )
    success: bool = Field(
        ..., description="Whether the scan command executed without process error"
    )
    findings: List[Dict[str, Any]] = Field(
        default_factory=list, description="List of vulnerabilities found"
    )
    error: Optional[str] = Field(None, description="Error message if the scan failed")
    command: str = Field(..., description="The nuclei command that was executed")
    raw_output: str = Field(..., description="Raw JSON output from nuclei")


# Helper functions to build command parts, reducing complexity of _build_nuclei_command
def _add_target_flags(cmd: List[str], params: NucleiScanParams) -> None:
    """Add target-related flags to the Nuclei command."""
    cmd.extend(["-target", params.target])
    if params.exclude_hosts:
        cmd.extend(["-exclude-hosts", ",".join(params.exclude_hosts)])
    if params.scan_all_ips:
        cmd.append("-scan-all-ips")
    if params.ip_version:
        cmd.extend(["-ip-version", ",".join(params.ip_version)])


def _add_template_flags(cmd: List[str], params: NucleiScanParams) -> None:
    """Add template selection/filtering flags."""
    if params.new_templates:
        cmd.append("-new-templates")
    if params.new_templates_version:
        cmd.extend(["-new-templates-version", ",".join(params.new_templates_version)])
    if params.automatic_scan:
        cmd.append("-automatic-scan")
    if params.templates:
        cmd.extend(["-templates", ",".join(params.templates)])
    if params.template_url:
        cmd.extend(["-template-url", ",".join(params.template_url)])
    if params.workflows:
        cmd.extend(["-workflows", ",".join(params.workflows)])
    if params.workflow_url:
        cmd.extend(["-workflow-url", ",".join(params.workflow_url)])
    if params.validate_templates:
        cmd.append("-validate")
    if params.no_strict_syntax:
        cmd.append("-no-strict-syntax")


# - Function complexity is high due to numerous filtering flags.
def _add_filter_flags(cmd: List[str], params: NucleiScanParams) -> None:  # noqa: C901
    """Add filtering flags (author, tags, severity, etc.)."""
    if params.author:
        cmd.extend(["-author", ",".join(params.author)])
    if params.tags:
        cmd.extend(["-tags", ",".join(params.tags)])
    if params.exclude_tags:
        cmd.extend(["-exclude-tags", ",".join(params.exclude_tags)])
    if params.include_tags:
        cmd.extend(["-include-tags", ",".join(params.include_tags)])
    if params.template_id:
        cmd.extend(["-template-id", ",".join(params.template_id)])
    if params.exclude_id:
        cmd.extend(["-exclude-id", ",".join(params.exclude_id)])
    if params.include_templates:
        cmd.extend(["-include-templates", ",".join(params.include_templates)])
    if params.exclude_templates:
        cmd.extend(["-exclude-templates", ",".join(params.exclude_templates)])
    if params.exclude_matchers:
        cmd.extend(["-exclude-matchers", ",".join(params.exclude_matchers)])
    if params.severity:
        cmd.extend(["-severity", ",".join(params.severity)])
    if params.exclude_severity:
        cmd.extend(["-exclude-severity", ",".join(params.exclude_severity)])
    if params.protocol_type:
        cmd.extend(["-type", ",".join(params.protocol_type)])
    if params.exclude_type:
        cmd.extend(["-exclude-type", ",".join(params.exclude_type)])
    if params.template_condition:
        cmd.extend(["-template-condition", ",".join(params.template_condition)])


def _add_output_flags(cmd: List[str], params: NucleiScanParams) -> None:
    """Add output configuration flags."""
    if params.store_resp:
        cmd.append("-store-resp")
    if params.store_resp_dir:
        cmd.extend(["-store-resp-dir", params.store_resp_dir])
    if params.omit_raw:
        cmd.append("-omit-raw")
    if params.omit_template:
        cmd.append("-omit-template")
    if params.matcher_status:
        cmd.append("-matcher-status")
    if params.redact_keys:
        cmd.extend(["-redact", ",".join(params.redact_keys)])


# - Function complexity is high due to numerous general config flags.
def _add_general_flags(cmd: List[str], params: NucleiScanParams) -> None:  # noqa: C901
    """Add general configuration flags (redirects, headers, network, etc.)."""
    if params.follow_redirects:
        cmd.append("-follow-redirects")
    if params.follow_host_redirects:
        cmd.append("-follow-host-redirects")
    if params.max_redirects is not None:
        cmd.extend(["-max-redirects", str(params.max_redirects)])
    if params.disable_redirects:
        cmd.append("-disable-redirects")
    if params.header:
        for h in params.header:
            cmd.extend(["-header", h])
    if params.system_resolvers:
        cmd.append("-system-resolvers")
    if params.disable_clustering:
        cmd.append("-disable-clustering")
    if params.passive:
        cmd.append("-passive")
    if params.force_http2:
        cmd.append("-force-http2")
    if params.env_vars:
        cmd.append("-env-vars")
    if params.restrict_local_network_access:
        cmd.append("-restrict-local-network-access")
    if params.interface:
        cmd.extend(["-interface", params.interface])
    if params.attack_type:
        cmd.extend(["-attack-type", params.attack_type])
    if params.source_ip:
        cmd.extend(["-source-ip", params.source_ip])
    if params.response_size_read is not None:
        cmd.extend(["-response-size-read", str(params.response_size_read)])


def _add_interactsh_flags(cmd: List[str], params: NucleiScanParams) -> None:
    """Add Interactsh related flags."""
    if params.no_interactsh:
        cmd.append("-no-interactsh")
    else:  # Only add server/token if interactsh is enabled
        if params.interactsh_server:
            cmd.extend(["-interactsh-server", params.interactsh_server])
        if params.interactsh_token:
            cmd.extend(["-interactsh-token", params.interactsh_token])
        if params.interactions_cache_size is not None:
            cmd.extend(
                [
                    "-interactions-cache-size",
                    str(params.interactions_cache_size),
                ]
            )
        if params.interactions_eviction is not None:
            cmd.extend(["-interactions-eviction", str(params.interactions_eviction)])
        if params.interactions_poll_duration is not None:
            cmd.extend(
                [
                    "-interactions-poll-duration",
                    str(params.interactions_poll_duration),
                ]
            )
        if params.interactions_cooldown_period is not None:
            cmd.extend(
                [
                    "-interactions-cooldown-period",
                    str(params.interactions_cooldown_period),
                ]
            )


def _add_fuzz_uncover_flags(cmd: List[str], params: NucleiScanParams) -> None:
    """Add Fuzzing and Uncover related flags."""
    # Fuzzing
    if params.dast:
        cmd.append("-dast")
    if params.fuzzing_type:
        cmd.extend(["-fuzzing-type", params.fuzzing_type])
    if params.fuzzing_mode:
        cmd.extend(["-fuzzing-mode", params.fuzzing_mode])

    # Uncover
    if params.uncover:
        cmd.append("-uncover")
    if params.uncover_query:
        cmd.extend(["-uncover-query", ",".join(params.uncover_query)])
    if params.uncover_engine:
        cmd.extend(["-uncover-engine", ",".join(params.uncover_engine)])
    if params.uncover_field:
        cmd.extend(["-uncover-field", params.uncover_field])
    if params.uncover_limit is not None:
        cmd.extend(["-uncover-limit", str(params.uncover_limit)])


def _add_rate_limit_flags(cmd: List[str], params: NucleiScanParams) -> None:
    """Add rate limiting flags."""
    if params.rate_limit:  # Always has a default
        cmd.extend(["-rate-limit", str(params.rate_limit)])
    if params.bulk_size is not None:
        cmd.extend(["-bulk-size", str(params.bulk_size)])
    if params.concurrency is not None:
        cmd.extend(["-concurrency", str(params.concurrency)])
    if params.headless_bulk_size is not None:
        cmd.extend(["-headless-bulk-size", str(params.headless_bulk_size)])
    if params.headless_concurrency is not None:
        cmd.extend(["-headless-concurrency", str(params.headless_concurrency)])
    if params.payload_concurrency is not None:
        cmd.extend(["-payload-concurrency", str(params.payload_concurrency)])
    if params.probe_concurrency is not None:
        cmd.extend(["-probe-concurrency", str(params.probe_concurrency)])


# - Function complexity is high due to numerous optimization flags.
def _add_optimization_flags(  # noqa: C901
    cmd: List[str], params: NucleiScanParams
) -> None:
    """Add optimization flags."""
    if params.timeout:  # Always has a default
        cmd.extend(["-timeout", str(params.timeout)])
    if params.retries is not None:
        cmd.extend(["-retries", str(params.retries)])
    if params.leave_default_ports:
        cmd.append("-leave-default-ports")
    if params.max_host_error is not None:
        cmd.extend(["-max-host-error", str(params.max_host_error)])
    if params.track_error:
        cmd.extend(["-track-error", ",".join(params.track_error)])
    if params.no_mhe:
        cmd.append("-no-mhe")
    if params.project:
        cmd.append("-project")
    if params.project_path:
        cmd.extend(["-project-path", params.project_path])
    if params.stop_at_first_match:
        cmd.append("-stop-at-first-match")
    if params.stream:
        cmd.append("-stream")
    if params.scan_strategy:
        cmd.extend(["-scan-strategy", params.scan_strategy])
    if params.input_read_timeout:
        cmd.extend(["-input-read-timeout", params.input_read_timeout])
    if params.no_httpx:
        cmd.append("-no-httpx")
    if params.no_stdin:
        cmd.append("-no-stdin")


def _add_headless_flags(cmd: List[str], params: NucleiScanParams) -> None:
    """Add headless browser flags."""
    if params.headless:
        cmd.append("-headless")
    if params.page_timeout is not None:
        cmd.extend(["-page-timeout", str(params.page_timeout)])
    if params.show_browser:
        cmd.append("-show-browser")
    if params.system_chrome:
        cmd.append("-system-chrome")


# - Function complexity is high due to numerous debug/proxy flags.
def _add_debug_flags(cmd: List[str], params: NucleiScanParams) -> None:  # noqa: C901
    """Add debugging and proxy flags."""
    if params.debug:
        cmd.append("-debug")
    if params.debug_req:
        cmd.append("-debug-req")
    if params.debug_resp:
        cmd.append("-debug-resp")
    if params.proxy:
        for p in params.proxy:
            cmd.extend(["-proxy", p])
    if params.proxy_internal:
        cmd.append("-proxy-internal")
    if params.hang_monitor:
        cmd.append("-hang-monitor")
    if params.verbose:
        cmd.append("-verbose")  # Note: Nuclei uses -v, but schema uses 'verbose'
    if params.show_var_dump:
        cmd.append("-show-var-dump")
    if params.var_dump_limit is not None:
        cmd.extend(["-var-dump-limit", str(params.var_dump_limit)])


# Refactored to use helper functions for clarity and reduced complexity
def _build_nuclei_command(params: NucleiScanParams) -> List[str]:
    """Build the Nuclei command list based on provided parameters.

    Args:
        params: The NucleiScanParams object containing the scan configuration.

    Returns:
        A list of strings representing the command and its arguments.
    """
    nuclei_path = os.environ.get("NUCLEI_PATH", "nuclei")
    cmd = [nuclei_path]

    # Call helper functions to add flags based on parameters
    _add_target_flags(cmd, params)
    _add_template_flags(cmd, params)
    _add_filter_flags(cmd, params)
    _add_output_flags(cmd, params)
    _add_general_flags(cmd, params)
    _add_interactsh_flags(cmd, params)
    _add_fuzz_uncover_flags(cmd, params)
    _add_rate_limit_flags(cmd, params)
    _add_optimization_flags(cmd, params)
    _add_headless_flags(cmd, params)
    _add_debug_flags(cmd, params)

    # --- Mandatory Flags for this tool ---
    # Always output JSON for parsing
    cmd.append("-jsonl")
    # Disable progress bar for cleaner output capture
    # cmd.append("-no-pb")
    # No color codes in output
    cmd.append("-no-color")
    # Ensure stats are not printed to stdout (interferes with JSONL)
    cmd.append("-stats-json")  # Outputs stats to separate file/stderr

    # Optional: Include update checks/disables if needed
    # cmd.append("-disable-update-check")

    return cmd


# The nuclei_scan_tool function remains largely the same, calling the
# refactored _build_nuclei_command
async def nuclei_scan_tool(  # noqa: C901
    ctx: RunContext[Any], params: NucleiScanParams
) -> NucleiResult:
    """
    Run a Nuclei security scan against the specified target.

    This tool uses Nuclei (https://github.com/projectdiscovery/nuclei) to scan
    networks, domains, or URLs for security vulnerabilities. It requires nuclei
    to be installed on the system.

    Args:
        ctx: Run context
        params: Parameters for the scan

    Returns:
        NucleiResult: The results of the nuclei scan
    """
    cmd = _build_nuclei_command(params)

    # For simulated scan in testing environments
    if os.getenv("AGENT_ENV") == "test":
        test_findings_json = json.dumps(
            [
                {
                    "template-id": "test-vuln-1",
                    "name": "Test Vulnerability 1",
                    "severity": "high",
                    "description": "This is a test vulnerability",
                    "tags": ["test", "cve"],
                    "reference": ["https://example.com/vuln1"],
                    "cve": ["CVE-2023-12345"],
                }
            ]
        )
        return NucleiResult(
            scan_status="success_with_findings",
            success=True,
            findings=[  # Simulate structure if needed
                {
                    "template-id": "test-vuln-1",
                    "name": "Test Vulnerability 1",
                    "severity": "high",
                }
            ],
            command=" ".join(cmd),
            raw_output=test_findings_json,  # Use valid JSON
        )

    # Run the command
    temp_file = None  # Initialize outside try
    try:
        # Sanitize target for filename
        sanitized_target = params.target.replace("/", "_").replace(":", "_")
        temp_file = f"/tmp/nuclei_scan_{sanitized_target}.json"

        # Append output file to command
        cmd_with_output = [*cmd, "-o", temp_file]

        cmd_str = " ".join(cmd_with_output)

        process = await asyncio.create_subprocess_exec(
            *cmd_with_output,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        stdout, stderr = await process.communicate()

        # Determine explicit status based on return code and findings
        findings = []  # Initialize findings list
        raw_content = ""  # Initialize raw_content
        explicit_status: Literal[
            "success_with_findings", "success_no_findings", "error"
        ]

        if process.returncode == 0:
            # Try reading results file only if command succeeded
            try:
                with open(temp_file) as f:
                    raw_content = f.read()
                for line in raw_content.strip().splitlines():
                    if line.strip():
                        try:
                            findings.append(json.loads(line))
                        except json.JSONDecodeError:
                            # Log or handle lines that aren't valid JSON if necessary
                            logger.warning(f"Skipping invalid JSON line: {line}")
                # Set status based on findings
                if findings:
                    explicit_status = "success_with_findings"
                else:
                    explicit_status = "success_no_findings"

                return NucleiResult(
                    scan_status=explicit_status,
                    success=True,
                    findings=findings,
                    command=cmd_str,
                    raw_output=raw_content,
                    error=None,  # Explicitly None on success
                )
            except Exception as e:
                # Error reading/processing the results file
                logger.error(f"Error processing results file {temp_file}: {e!s}")
                return NucleiResult(
                    scan_status="error",
                    success=False,  # Indicate failure even if process exited 0
                    findings=[],
                    command=cmd_str,
                    error=f"Error processing results file {temp_file}: {e!s}",
                    raw_output=raw_content,  # Include potentially partial content
                )
        else:
            # Process failed (non-zero return code)
            explicit_status = "error"
            error_message = stderr.decode().strip()
            stdout_message = stdout.decode().strip()
            logger.error(f"Nuclei process failed. Stderr: {error_message}")
            return NucleiResult(
                scan_status=explicit_status,
                success=False,
                findings=[],
                command=cmd_str,
                error=error_message,
                raw_output=stdout_message,  # Capture stdout even on error
            )

    except Exception as e:
        # Catch broader errors like subprocess creation failure
        logger.exception(f"Error executing nuclei: {e!s}")
        return NucleiResult(
            scan_status="error",
            success=False,
            findings=[],
            command=" ".join(cmd),  # Use original cmd if exec failed early
            error=f"Error executing nuclei: {e!s}",
            raw_output="",
        )
    finally:
        # Clean up the temporary file
        if temp_file and os.path.exists(temp_file):
            try:
                os.remove(temp_file)
            except OSError:
                pass


class DomainInfoParams(BaseModel):
    """Parameters for parse_domain_info_tool."""

    fields_to_extract: List[str] = Field(
        ..., description="List of fields to extract from domain_info"
    )


async def parse_domain_info_tool(
    ctx: RunContext[Dict[str, Any]], params: DomainInfoParams
) -> Dict[str, Any]:
    """Parse and extract specific fields from domain_info stored in deps."""
    domain_info = ctx.deps.get("domain_info")
    if not domain_info:
        return {"message": "No domain info in deps", "status": "no_data"}

    extracted_data = {}
    for field in params.fields_to_extract:
        if field in domain_info:
            extracted_data[field] = domain_info[field]

    if not extracted_data:
        return {
            "message": "None of the requested fields found in domain info",
            "status": "no_matching_data",
            "available_fields": list(domain_info.keys()),
        }

    return extracted_data


# Create Tool instances for registration with Agent
nuclei_scan_tool_instance = Tool(nuclei_scan_tool)
parse_domain_info_tool_instance = Tool(parse_domain_info_tool)

# Get logger instance
logger = logging.getLogger(__name__)
