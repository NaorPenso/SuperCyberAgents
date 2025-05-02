# Exposure Agent Usage Example

This example demonstrates how to use the Exposure Agent for comprehensive security analysis of an organization's domains.

## Prerequisites

Ensure you have the following environment variables set:

```bash
export VIRUSTOTAL_API_KEY="your_api_key_here"
export SHODAN_API_KEY="your_api_key_here" 
export HIBP_API_KEY="your_api_key_here"  # Optional
```

## CLI Usage

```bash
# Analyze a single domain with standard depth
poetry run python -m cli.main agent run exposure_agent --input '{"organization_name": "Acme Corp", "domains": ["example.com"]}'

# Analyze multiple domains with comprehensive analysis
poetry run python -m cli.main agent run exposure_agent --input-file inputs/exposure_analysis.json
```

Example content for `inputs/exposure_analysis.json`:

```json
{
  "organization_name": "Acme Corporation",
  "domains": ["acme.com", "acme.org", "acmecorp.net"],
  "email_domains": ["acme.com"],
  "include_subdomains": true,
  "analysis_depth": "comprehensive"
}
```

## API Usage

### Request

```http
POST /agents/exposure_agent/invoke HTTP/1.1
Host: localhost:8000
Content-Type: application/json

{
  "input": {
    "organization_name": "Acme Corporation",
    "domains": ["acme.com", "acme.org"],
    "include_subdomains": true,
    "analysis_depth": "standard"
  }
}
```

### Response

```json
{
  "output": {
    "organization_name": "Acme Corporation",
    "overall_risk_score": 42.5,
    "domain_results": [
      {
        "domain": "acme.com",
        "whois_data": {
          "domain_name": "acme.com",
          "registrar": "Example Registrar Inc.",
          "creation_date": "2000-04-17T12:00:00Z",
          "expiration_date": "2025-04-17T12:00:00Z",
          "name_servers": ["ns1.example.com", "ns2.example.com"],
          "status": ["clientTransferProhibited"],
          "emails": ["admin@acme.com"],
          "dnssec": "unsigned",
          "updated_date": "2023-04-17T12:00:00Z"
        },
        "threat_score": 15.2,
        "threat_categories": ["none"],
        "is_expired": false,
        "is_suspicious": false,
        "exposure_details": {
          "open_ports": [80, 443, 22],
          "exposed_services": ["http", "https", "ssh"],
          "vulnerabilities": []
        },
        "subdomains": [
          "www.acme.com",
          "mail.acme.com",
          "support.acme.com",
          "blog.acme.com"
        ],
        "email_security": {
          "spf": {"valid": true, "policy": "hard fail"},
          "dkim": {"detected": true, "valid": true},
          "dmarc": {"valid": true, "policy": "reject"}
        }
      },
      {
        "domain": "acme.org",
        "whois_data": {
          "domain_name": "acme.org",
          "registrar": "Example Registrar Inc.",
          "creation_date": "2008-06-23T12:00:00Z",
          "expiration_date": "2024-06-23T12:00:00Z",
          "name_servers": ["ns1.example.com", "ns2.example.com"],
          "status": ["clientTransferProhibited"],
          "emails": ["admin@acme.com"],
          "dnssec": "unsigned",
          "updated_date": "2023-06-23T12:00:00Z"
        },
        "threat_score": 32.7,
        "threat_categories": ["suspicious"],
        "is_expired": false,
        "is_suspicious": false,
        "exposure_details": {
          "open_ports": [80, 443],
          "exposed_services": ["http", "https"],
          "vulnerabilities": ["CVE-2022-12345"]
        },
        "subdomains": [
          "www.acme.org",
          "portal.acme.org",
          "dev.acme.org"
        ],
        "email_security": null
      }
    ],
    "email_security_posture": {
      "acme.com": {
        "spf": {
          "record": "v=spf1 include:_spf.acme.com -all",
          "valid": true,
          "policy": "hard fail"
        },
        "dkim": {
          "detected": true,
          "valid": true
        },
        "dmarc": {
          "record": "v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@acme.com",
          "valid": true,
          "policy": "reject"
        },
        "mta_sts": false,
        "recommendations": [
          "Implement MTA-STS to secure mail transport"
        ]
      }
    },
    "critical_findings": [
      "Domain acme.org has vulnerabilities: CVE-2022-12345"
    ],
    "recommendations": [
      "Address identified vulnerabilities on acme.org: CVE-2022-12345",
      "acme.com: Implement MTA-STS to secure mail transport",
      "Consider implementing a formal security monitoring program"
    ],
    "processed_at": "2023-08-15T14:37:42.123456Z"
  }
}
```

## Programmatic Usage

```python
import asyncio
import os
from schemas.exposure_agent_schemas import ExposureAgentInput
from core.agent_registry import get_agent

async def run_exposure_analysis():
    # Ensure environment variables are set
    assert "VIRUSTOTAL_API_KEY" in os.environ, "VIRUSTOTAL_API_KEY not set"
    assert "SHODAN_API_KEY" in os.environ, "SHODAN_API_KEY not set"
    
    # Get the registered agent
    exposure_agent = get_agent("exposure_agent")
    
    # Prepare input
    input_data = ExposureAgentInput(
        organization_name="Acme Corporation",
        domains=["acme.com", "acme.org"],
        include_subdomains=True,
        analysis_depth="standard"
    )
    
    # Run the agent
    result = exposure_agent.run(input_data)
    
    # Process results
    print(f"Analysis completed with risk score: {result.overall_risk_score}/100")
    print("Critical findings:")
    for finding in result.critical_findings:
        print(f"- {finding}")
    
    print("\nRecommendations:")
    for recommendation in result.recommendations:
        print(f"- {recommendation}")

if __name__ == "__main__":
    asyncio.run(run_exposure_analysis())
``` 