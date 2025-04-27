# IP Lookup Tool

This directory contains the implementation for the `ip_lookup_tool`.

## Purpose

This tool looks up the reputation of a given IP address using an external Threat Intelligence API.
It requires an API endpoint and potentially an API key (via the `IP_LOOKUP_API_KEY` environment variable) to be configured.

## Configuration

Refer to `config/tools/ip_lookup_tool.yaml` for configuration options such as the API endpoint URL, authentication requirements, and timeout.

## Schemas

Input/Output schemas (`IPLookupInput`, `IPLookupOutput`) are defined in `schemas/tool_schemas.py`.

## Usage Notes

- Ensure the API endpoint in the configuration is correct.
- If `auth_required` is true in the config, set the `IP_LOOKUP_API_KEY` environment variable. 