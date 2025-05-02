"""Pydantic schemas for Domain Analysis results."""

from typing import List, Optional

from pydantic import BaseModel, Field


class CertificateInfo(BaseModel):
    """Schema for crt.sh certificate details."""

    issuer_name: Optional[str] = Field(
        None, description="The name of the certificate issuer."
    )
    common_names: List[str] = Field(
        description="List of common names (domains) covered by the certificate."
    )
    not_before: Optional[str] = Field(
        None, description="Certificate validity start date (ISO 8601 format)."
    )
    not_after: Optional[str] = Field(
        None, description="Certificate validity end date (ISO 8601 format)."
    )
    serial_number: Optional[str] = Field(
        None, description="The serial number of the certificate."
    )


class IPWhoisInfo(BaseModel):
    """Schema for IP Whois information."""

    ip_address: Optional[str] = Field(
        None, description="The IP address resolved from the domain."
    )
    asn: Optional[str] = Field(None, description="Autonomous System Number (ASN).")
    asn_cidr: Optional[str] = Field(None, description="ASN CIDR block.")
    asn_country_code: Optional[str] = Field(None, description="ASN country code.")
    asn_description: Optional[str] = Field(None, description="Description of the ASN.")
    nets: Optional[List[dict]] = Field(None, description="Network allocation details.")


class DNSSecurityInfo(BaseModel):
    """Schema for DNS Security checks (e.g., DNSSEC)."""

    dnssec_enabled: Optional[bool] = Field(
        None, description="Indicates if DNSSEC is enabled and validated for the domain."
    )
    # Add other relevant DNS security fields as needed (e.g., specific record checks)


class EmailSecurityInfo(BaseModel):
    """Schema for Email Security checks (SPF, DMARC)."""

    spf_record: Optional[str] = Field(None, description="The retrieved SPF record.")
    spf_valid: Optional[bool] = Field(
        None, description="Indicates if the SPF record syntax is valid."
    )
    dmarc_record: Optional[str] = Field(None, description="The retrieved DMARC record.")
    dmarc_policy: Optional[str] = Field(
        None, description="The effective DMARC policy (e.g., none, quarantine, reject)."
    )
    dmarc_valid: Optional[bool] = Field(
        None, description="Indicates if the DMARC record syntax is valid."
    )


class ShodanHostInfo(BaseModel):
    """Schema for relevant Shodan host information."""

    ip_address: str = Field(description="The IP address queried.")
    organization: Optional[str] = Field(None, description="Organization owning the IP.")
    os: Optional[str] = Field(None, description="Operating system identified.")
    ports: List[int] = Field(
        default_factory=list, description="List of open ports identified."
    )
    tags: List[str] = Field(
        default_factory=list, description="Tags associated with the host by Shodan."
    )
    vulns: List[str] = Field(
        default_factory=list,
        description="List of potential vulnerabilities (CVEs) identified.",
    )
    last_update: Optional[str] = Field(
        None, description="Timestamp of the last Shodan update."
    )
    country_name: Optional[str] = Field(None, description="Country name.")
    city: Optional[str] = Field(None, description="City name.")


class VirusTotalUrlAnalysis(BaseModel):
    """Schema for VirusTotal URL analysis summary."""

    url: str = Field(description="The URL submitted for analysis.")
    malicious_count: Optional[int] = Field(
        None, description="Number of engines detecting the URL as malicious."
    )
    suspicious_count: Optional[int] = Field(
        None, description="Number of engines detecting the URL as suspicious."
    )
    harmless_count: Optional[int] = Field(
        None, description="Number of engines detecting the URL as harmless."
    )
    undetected_count: Optional[int] = Field(
        None, description="Number of engines that did not detect the URL."
    )
    last_analysis_date: Optional[str] = Field(
        None, description="Timestamp of the last analysis (ISO 8601 format or epoch)."
    )
    # Example: Consider adding a direct link to the VT report if useful
    # report_link: Optional[str] = Field(
    #     None, description="Link to the full VirusTotal report."
    # )


class DomainAnalysisResult(BaseModel):
    """Comprehensive results of the domain analysis."""

    domain: str = Field(description="The domain that was analyzed.")
    ip_info: Optional[IPWhoisInfo] = Field(
        None, description="IP Whois information for the domain's primary IP."
    )
    shodan_info: Optional[ShodanHostInfo] = Field(
        None, description="Shodan host information for the primary IP."
    )
    vt_analysis: Optional[VirusTotalUrlAnalysis] = Field(
        None, description="VirusTotal URL analysis summary for the domain."
    )
    certificates: List[CertificateInfo] = Field(
        default_factory=list, description="List of relevant SSL/TLS certificates found."
    )
    dns_security: Optional[DNSSecurityInfo] = Field(
        None, description="DNS security status."
    )
    email_security: Optional[EmailSecurityInfo] = Field(
        None, description="Email security status (SPF, DMARC)."
    )
    analysis_summary: str = Field(
        description="A concise summary of the key findings from the analysis."
    )
