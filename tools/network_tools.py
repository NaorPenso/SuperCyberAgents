"""Network security tools for the NetworkSecurityAgent.

This module provides tools for network security scanning and analysis, primarily
using Nuclei from ProjectDiscovery to scan networks, endpoints, and servers for
vulnerabilities.
"""

import asyncio
import json
import os
import subprocess
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field
from pydantic_ai.tools import RunContext, Tool


class NucleiScanParams(BaseModel):
    """Parameters for nuclei_scan_tool."""

    target: str = Field(..., description="URL, domain, or IP to scan")
    templates: Optional[List[str]] = Field(
        default=None,
        description="Specific templates to use (e.g., ['cves', 'vulnerabilities'])",
    )
    severity: Optional[List[str]] = Field(
        default=None,
        description="Filter by severity: 'info', 'low', 'medium', 'high', 'critical'",
    )
    rate_limit: int = Field(
        default=150, description="Maximum number of requests per minute (default: 150)"
    )
    timeout: int = Field(
        default=5, description="Timeout in seconds for each request (default: 5)"
    )


class NucleiResult(BaseModel):
    """Result from a nuclei scan."""

    success: bool = Field(..., description="Whether the scan completed successfully")
    findings: List[Dict[str, Any]] = Field(
        default_factory=list, description="List of vulnerabilities found"
    )
    error: Optional[str] = Field(None, description="Error message if the scan failed")
    command: str = Field(..., description="The nuclei command that was executed")
    raw_output: str = Field(..., description="Raw JSON output from nuclei")


async def nuclei_scan_tool(
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
    # Build the command
    cmd = ["nuclei", "-target", params.target, "-json"]

    # Add templates if specified
    if params.templates:
        for template in params.templates:
            cmd.extend(["-t", template])

    # Add severity filter if specified
    if params.severity:
        cmd.extend(["-s", ",".join(params.severity)])

    # Add rate limit
    cmd.extend(["-rate-limit", str(params.rate_limit)])

    # Add timeout
    cmd.extend(["-timeout", str(params.timeout)])

    # For simulated scan in testing environments
    if os.getenv("AGENT_ENV") == "test":
        return NucleiResult(
            success=True,
            findings=[
                {
                    "template-id": "test-vuln-1",
                    "name": "Test Vulnerability 1",
                    "severity": "high",
                    "description": "This is a test vulnerability",
                    "tags": ["test", "cve"],
                    "reference": ["https://example.com/vuln1"],
                    "cve": ["CVE-2023-12345"],
                }
            ],
            command=" ".join(cmd),
            raw_output='{"findings": [{"template-id": "test-vuln-1", "name": "Test Vulnerability 1"}]}',
        )

    # Run the command
    try:
        # Create a temporary file to store the JSON output
        temp_file = (
            f"/tmp/nuclei_scan_{params.target.replace('/', '_').replace(':', '_')}.json"
        )

        # Append output file to command
        cmd.extend(["-o", temp_file])

        # Convert to a string for logging
        cmd_str = " ".join(cmd)

        # Run nuclei as a subprocess
        process = await asyncio.create_subprocess_exec(
            *cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            return NucleiResult(
                success=False,
                command=cmd_str,
                error=stderr.decode(),
                raw_output=stdout.decode(),
            )

        # Read the results from the temporary file
        try:
            with open(temp_file) as f:
                raw_content = f.read()

            # Process the JSON results (one JSON object per line)
            findings = []
            for line in raw_content.splitlines():
                if line.strip():
                    findings.append(json.loads(line))

            return NucleiResult(
                success=True, findings=findings, command=cmd_str, raw_output=raw_content
            )
        except Exception as e:
            return NucleiResult(
                success=False,
                command=cmd_str,
                error=f"Error processing results: {e!s}",
                raw_output=raw_content if "raw_content" in locals() else "",
            )
        finally:
            # Clean up the temporary file
            if os.path.exists(temp_file):
                os.remove(temp_file)

    except Exception as e:
        return NucleiResult(
            success=False,
            command=" ".join(cmd),
            error=f"Error executing nuclei: {e!s}",
            raw_output="",
        )


class DomainInfoParams(BaseModel):
    """Parameters for parse_domain_info_tool."""

    pass  # No parameters needed as this tool uses the deps


async def parse_domain_info_tool(
    ctx: RunContext[Dict[str, Any]], params: DomainInfoParams
) -> Dict[str, Any]:
    """
    Parse domain information from DomainAnalyzerAgent results.

    This tool extracts relevant information from domain analysis results
    to help with security scanning and assessment.

    Args:
        ctx: Run context containing domain_info in deps
        params: No parameters needed

    Returns:
        Dict[str, Any]: Structured domain information relevant for security assessment
    """
    domain_info = ctx.deps.get("domain_info")

    if not domain_info:
        return {
            "status": "no_data",
            "message": "No domain information available in dependencies",
        }

    # Extract security-relevant information
    security_info = {
        "status": "success",
        "domain": domain_info.get("domain", "unknown"),
        "subdomains": domain_info.get("subdomains", []),
        "ip_addresses": domain_info.get("ip_addresses", []),
        "dns_records": domain_info.get("dns_records", {}),
        "technologies": domain_info.get("technologies", []),
        "ssl_info": domain_info.get("ssl_info", {}),
        "security_headers": domain_info.get("security_headers", {}),
        "open_ports": domain_info.get("open_ports", []),
    }

    return security_info


# Create Tool instances
nuclei_scan_tool = Tool(nuclei_scan_tool)
parse_domain_info_tool = Tool(parse_domain_info_tool)
