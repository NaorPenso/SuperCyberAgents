# Domain WHOIS Agent (SuperCyberAgents)

This directory contains the implementation for the `domain_whois_agent` within the SuperCyberAgents framework.

## Purpose

This agent retrieves and structures WHOIS registration data for a given domain name. It primarily utilizes the `whois_lookup_tool` to perform the lookup and then maps the results into a standardized output format.

LLM usage is minimal in the current implementation, mainly for potential future enhancements or error summarization (though currently, errors are passed directly from the tool).

## Configuration

Refer to `config/agents/domain_whois_agent.yaml` for agent configuration options, including:
- LLM provider and model
- Tool mapping (`whois_lookup_tool` aliased as `whois_lookup`)
- Input/Output schema references

## Schemas

- **Input:** `DomainWhoisInput` (defined in `schemas/domain_whois_schemas.py`) - Requires a `domain` string.
- **Output:** `DomainWhoisOutput` (defined in `schemas/domain_whois_schemas.py`) - Provides structured WHOIS data or an error message.

## Tools Used

- `whois_lookup_tool`: The core tool used to fetch WHOIS data. See `tools/whois_lookup_tool/README.md` for details.

## Usage Notes

- The agent expects the `whois_lookup_tool` to be configured and available.
- Ensure the `python-whois` library is installed (`poetry add python-whois`).
- The agent directly maps the output fields from the `whois_lookup_tool` to its own output schema. 