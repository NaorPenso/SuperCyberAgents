"""Tools for performing domain analysis tasks."""

import asyncio

# Add base64 for VT URL ID encoding
import base64
import logging
import os
import socket
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import dns.resolver
import httpx

# Add Shodan import
import shodan
from ipwhois import IPWhois
from ipwhois.exceptions import ASNRegistryError, IPDefinedError, WhoisRateLimitError

# Project Imports (assuming schemas are used for type hinting return dicts)
# from schemas.domain_analysis import CertificateInfo, IPWhoisInfo, etc.


logger = logging.getLogger(__name__)


# --- Helper for DNS lookups ---
async def _query_dns(domain: str, record_type: str) -> List[str]:
    """Helper function to perform async DNS queries."""
    try:
        # Run the synchronous dns.resolver call in a separate thread
        resolver = dns.resolver.Resolver()
        answers = await asyncio.to_thread(resolver.resolve, domain, record_type)
        return [rdata.to_text().strip('"') for rdata in answers]
    except dns.resolver.NoAnswer:
        logger.debug(f"No {record_type} record found for {domain}")
        return []
    except dns.resolver.NXDOMAIN:
        logger.warning(f"Domain {domain} does not exist (NXDOMAIN).")
        return []
    except dns.exception.Timeout:
        logger.error(f"DNS query timeout for {record_type} at {domain}")
        return []
    except Exception as e: # pragma: no cover
        logger.exception(f"Error querying DNS {record_type} for {domain}: {e}")
        return []


# --- Tool Implementations ---


async def crt_sh_lookup(domain: str) -> List[Dict[str, Any]]:
    """Looks up SSL/TLS certificate information for a domain using crt.sh data.

    Args:
        domain: The domain name to query.

    Returns:
        A list of dictionaries, each representing a certificate found,
        matching the structure expected by CertificateInfo schema.
        Returns an empty list if no certificates are found or an error occurs.
    """
    logger.info(f"Looking up crt.sh certificates for {domain}")
    url = f"https://crt.sh/?q={domain}&output=json"
    certificates = []
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, timeout=30.0)
            response.raise_for_status()  # Raise exception for 4xx/5xx status
            data = response.json()

            if isinstance(data, list):
                for cert_data in data:
                    # Handle potential None value for common_name safely
                    common_name_str = cert_data.get("common_name")
                    common_names_list = common_name_str.split("\n") if common_name_str else []
                    name_value_list = cert_data.get("name_value", "").split("\n")

                    # Map crt.sh fields to our CertificateInfo structure
                    certificates.append(
                        {
                            "issuer_name": cert_data.get("issuer_name"),
                            "common_names": common_names_list + name_value_list,
                            "not_before": cert_data.get("not_before"),
                            "not_after": cert_data.get("not_after"),
                            "serial_number": cert_data.get("serial_number"),
                        }
                    )
            else:
                logger.warning(
                    f"crt.sh returned unexpected data format for {domain}: {type(data)}"
                )

    except httpx.HTTPStatusError as e:
        logger.error(
            f"HTTP error fetching crt.sh data for {domain}: "
            f"{e.response.status_code} - {e.request.url}"
        )
    except httpx.RequestError as e:
        logger.error(f"Network error fetching crt.sh data for {domain}: {e}")
    except Exception as e: # pragma: no cover
        logger.exception(f"Error processing crt.sh data for {domain}: {e}")

    # Clean up common names (remove empty strings, duplicates)
    for cert in certificates:
        cert["common_names"] = sorted(list(set(filter(None, cert["common_names"]))))

    logger.info(f"Found {len(certificates)} certificates for {domain} via crt.sh")
    return certificates


async def ipwhois_lookup(domain: str) -> Optional[Dict[str, Any]]:
    """Performs an IP Whois lookup for the primary IP address of a domain.

    Args:
        domain: The domain name to resolve and query.

    Returns:
        A dictionary containing IP Whois information matching IPWhoisInfo schema,
        or None if resolution/lookup fails.
    """
    logger.info(f"Performing IP Whois lookup for {domain}")
    ip_address = None
    try:
        # Resolve domain to IP - Use asyncio's loop for getaddrinfo
        loop = asyncio.get_running_loop()
        addr_info = await loop.getaddrinfo(domain, None, family=socket.AF_INET)
        if addr_info:
            ip_address = addr_info[0][4][0]
            logger.info(f"Resolved {domain} to {ip_address}")
        else:
            logger.warning(f"Could not resolve {domain} to an IP address.")
            return None

    except socket.gaierror as e:
        logger.warning(f"Could not resolve domain {domain}: {e}")
        return None
    except Exception as e: # pragma: no cover
        logger.exception(f"Unexpected error during domain resolution for {domain}: {e}")
        return None

    if ip_address:
        try:
            # Perform Whois lookup asynchronously
            # Note: IPWhois itself isn't inherently async, but the network calls can be.
            # For true async, one might need a different library or wrapper.
            # Here, we run the synchronous IPWhois in a thread.
            obj = IPWhois(ip_address)
            # Run the synchronous network I/O in a separate thread
            results = await asyncio.to_thread(obj.lookup_whois)

            # Map results to IPWhoisInfo structure
            return {
                "ip_address": ip_address,
                "asn": results.get("asn"),
                "asn_cidr": results.get("asn_cidr"),
                "asn_country_code": results.get("asn_country_code"),
                "asn_description": results.get("asn_description"),
                "nets": results.get("nets"),
            }
        except (ASNRegistryError, IPDefinedError, WhoisRateLimitError) as e:
            logger.warning(f"IP Whois lookup failed for {ip_address} ({domain}): {e}")
        except Exception as e: # pragma: no cover
            logger.exception(
                f"Error during IP Whois lookup for {ip_address} ({domain}): {e}"
            )

    return None


async def dns_security_check(domain: str) -> Optional[Dict[str, Any]]:
    """Checks DNS security configurations like DNSSEC for a domain.

    Args:
        domain: The domain name to check.

    Returns:
        A dictionary with DNS security status matching DNSSecurityInfo schema,
        or None if checks fail.
    """
    logger.info(f"Checking DNS security (DNSSEC) for {domain}")
    try:
        # Query for DNSKEY records. The presence indicates DNSSEC is likely used,
        # but full validation is complex and might require more checks.
        dnskey_records = await _query_dns(domain, "DNSKEY")
        dnssec_enabled = bool(dnskey_records)
        status_str = (
            "Enabled (found DNSKEY)" if dnssec_enabled else "Not Enabled (no DNSKEY)"
        )
        logger.info(f"DNSSEC status for {domain}: {status_str}")
        return {"dnssec_enabled": dnssec_enabled}
    except Exception as e: # pragma: no cover
        # Catch potential exceptions from _query_dns although it has internal handling
        logger.exception(f"Error during DNS security check for {domain}: {e}")
        return {"dnssec_enabled": None}  # Indicate check failed


async def _check_spf(domain: str) -> tuple[str | None, bool | None]:
    """Check SPF record for a domain."""
    spf_record = None
    spf_valid = None
    try:
        spf_records = await _query_dns(domain, "TXT")
        for record in spf_records:
            if record.lower().startswith("v=spf1"):
                spf_record = record
                spf_valid = True  # Basic assumption, not full validation
                logger.debug(f"Found SPF record for {domain}: {record}")
                break  # Assume only one SPF record
        if not spf_record:
            logger.info(f"No SPF record found for {domain}")
    except Exception as e: # pragma: no cover
        logger.exception(f"Error checking SPF for {domain}: {e}")
    return spf_record, spf_valid


async def _check_dmarc(domain: str) -> tuple[str | None, str | None, bool | None]:
    """Check DMARC record for a domain."""
    dmarc_record = None
    dmarc_policy = None
    dmarc_valid = None
    dmarc_domain = f"_dmarc.{domain}"
    try:
        dmarc_records = await _query_dns(dmarc_domain, "TXT")
        for record in dmarc_records:
            if record.lower().startswith("v=dmarc1"):
                dmarc_record = record
                dmarc_valid = True  # Basic assumption
                # Extract policy (simple check)
                if "p=reject" in record.lower():
                    dmarc_policy = "reject"
                elif "p=quarantine" in record.lower():
                    dmarc_policy = "quarantine"
                elif "p=none" in record.lower():
                    dmarc_policy = "none"
                logger.debug(f"Found DMARC record for {domain}: {record}")
                break  # Assume only one DMARC record
        if not dmarc_record:
            logger.info(f"No DMARC record found for {domain} (at {dmarc_domain})")
    except Exception as e: # pragma: no cover
        logger.exception(f"Error checking DMARC for {domain}: {e}")
    return dmarc_record, dmarc_policy, dmarc_valid


async def shodan_host_lookup(ip_address: str) -> Optional[Dict[str, Any]]:
    """Looks up host information for a given IP address using the Shodan API.

    Requires the SHODAN_API_KEY environment variable to be set.

    Args:
        ip_address: The IP address to query.

    Returns:
        A dictionary containing Shodan host information matching ShodanHostInfo schema,
        or None if the lookup fails or the API key is missing.
    """
    logger.info(f"Performing Shodan host lookup for {ip_address}")
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        logger.warning(
            "SHODAN_API_KEY environment variable not set. Skipping Shodan lookup."
        )
        return None

    try:
        api = shodan.Shodan(api_key)

        # Run the synchronous Shodan API call in a separate thread
        host_info = await asyncio.to_thread(api.host, ip_address)

        # Map results to ShodanHostInfo structure
        return {
            "ip_address": host_info.get("ip_str", ip_address),
            "organization": host_info.get("org"),
            "os": host_info.get("os"),
            "ports": host_info.get("ports", []),
            "tags": host_info.get("tags", []),
            "vulns": host_info.get("vulns", []),
            "last_update": host_info.get("last_update"),
            "country_name": host_info.get("country_name"),
            "city": host_info.get("city"),
        }

    except shodan.APIError as e:
        logger.error(f"Shodan API error for {ip_address}: {e}")
        # Handle specific errors like "No information available for that IP."
        if "No information available" in str(e):
            logger.info(f"No Shodan information available for IP: {ip_address}")
            return {
                "ip_address": ip_address
            }  # Return minimal info indicating lookup occurred
        return None  # Return None for other API errors (key invalid, etc.)
    except Exception as e: # pragma: no cover
        logger.exception(f"Unexpected error during Shodan lookup for {ip_address}: {e}")
        return None


async def virustotal_url_analysis(domain: str) -> Optional[Dict[str, Any]]:
    """Retrieves the latest VirusTotal analysis report for a given domain/URL.

    Constructs the URL as http://{domain} for analysis.
    Requires the VIRUSTOTAL_API_KEY environment variable to be set.

    Args:
        domain: The domain name to analyze.

    Returns:
        A dictionary containing VirusTotal URL analysis summary matching
        VirusTotalUrlAnalysis schema, or None if the lookup fails,
        the API key is missing, or the URL is not found on VirusTotal.
    """
    logger.info(f"Performing VirusTotal URL analysis for {domain}")
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        logger.warning(
            "VIRUSTOTAL_API_KEY environment variable not set. "
            "Skipping VirusTotal lookup."
        )
        return None

    # Construct the URL and the VT API v3 URL ID
    url_to_analyze = f"http://{domain}"  # Assume http for VT analysis
    try:
        # VT API v3 uses base64 of the URL (without padding) as the identifier
        url_id = base64.urlsafe_b64encode(url_to_analyze.encode()).decode().strip("=")
        vt_api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    except Exception as e:
        logger.error(f"Failed to encode URL for VirusTotal ID ({url_to_analyze}): {e}")
        return None

    headers = {"x-apikey": api_key}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(vt_api_url, headers=headers, timeout=30.0)

            if response.status_code == 404:
                logger.info(f"URL not found on VirusTotal: {url_to_analyze}")
                return {"url": url_to_analyze}  # Indicate lookup occurred but no report

            response.raise_for_status()  # Raise exception for other 4xx/5xx status
            data = response.json()

            if "data" in data and "attributes" in data["data"]:
                attributes = data["data"]["attributes"]
                stats = attributes.get("last_analysis_stats", {})
                last_analysis_ts = attributes.get("last_analysis_date")

                # Convert epoch timestamp to ISO format if needed
                analysis_date_str = None
                if last_analysis_ts:
                    try:
                        # Use fromtimestamp with timezone.utc
                        dt_object = datetime.fromtimestamp(
                            last_analysis_ts, timezone.utc
                        )
                        analysis_date_str = dt_object.isoformat()
                    except Exception: # pragma: no cover
                        logger.warning(
                            f"Could not parse VT last_analysis_date: {last_analysis_ts}"
                        )

                return {
                    "url": url_to_analyze,
                    "malicious_count": stats.get("malicious"),
                    "suspicious_count": stats.get("suspicious"),
                    "harmless_count": stats.get("harmless"),
                    "undetected_count": stats.get("undetected"),
                    "last_analysis_date": analysis_date_str,
                }
            else:
                logger.warning(
                    f"Unexpected VirusTotal API response structure for {url_to_analyze}"
                )
                return {"url": url_to_analyze}  # Indicate lookup but unexpected data

    except httpx.HTTPStatusError as e:
        logger.error(
            f"VirusTotal API HTTP error for {url_to_analyze}: "
            f"{e.response.status_code} - {e.request.url}"
        )
        return None
    except httpx.RequestError as e:
        logger.error(
            f"Network error fetching VirusTotal data for {url_to_analyze}: {e}"
        )
        return None
    except Exception as e: # pragma: no cover
        logger.exception(
            f"Unexpected error during VirusTotal URL analysis for {url_to_analyze}: {e}"
        )
        return None


async def email_security_check(domain: str) -> Optional[Dict[str, Any]]:
    """Checks email security configurations like SPF and DMARC for a domain.

    Args:
        domain: The domain name to check.

    Returns:
        A dictionary with email security status matching EmailSecurityInfo schema,
        or None if checks fail completely (though usually returns partial results).
    """
    logger.info(f"Checking email security (SPF/DMARC) for {domain}")

    # Concurrently check SPF and DMARC
    try:
        spf_result, dmarc_result = await asyncio.gather(
            _check_spf(domain), _check_dmarc(domain)
        )
    except Exception as e: # pragma: no cover
        # Handle potential errors from asyncio.gather itself, though unlikely here
        logger.exception(f"Error gathering email security checks for {domain}: {e}")
        # Return default/empty state if gathering fails catastrophically
        return {
            "spf_record": None,
            "spf_valid": None,
            "dmarc_record": None,
            "dmarc_policy": None,
            "dmarc_valid": None,
        }

    spf_record, spf_valid = spf_result
    dmarc_record, dmarc_policy, dmarc_valid = dmarc_result

    results: Dict[str, Any] = {
        "spf_record": spf_record,
        "spf_valid": spf_valid,
        "dmarc_record": dmarc_record,
        "dmarc_policy": dmarc_policy,
        "dmarc_valid": dmarc_valid,
    }

    return results


# Example usage if needed for local testing
# async def main(): # pragma: no cover
#     domain_to_test = "google.com"
#     email_sec = await email_security_check(domain_to_test)
#     print(f"Email Security for {domain_to_test}: {email_sec}")
#
# if __name__ == "__main__": # pragma: no cover
#     asyncio.run(main())
