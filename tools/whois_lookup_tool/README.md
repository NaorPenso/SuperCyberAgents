# Whois Lookup Tool

This directory contains the implementation for the `whois_lookup_tool`.

## Purpose

Performs a WHOIS lookup for a given domain name using the `python-whois` library.

## Configuration

Refer to `config/tools/whois_lookup_tool.yaml`.
This tool currently does not have specific configuration options beyond the standard ones (name, description, schemas).

## Schemas

Input/Output schemas (`WhoisLookupInput`, `WhoisLookupOutput`) are defined in `schemas/whois_lookup_schemas.py`.

## Dependencies

Requires the `python-whois` library. Install it using:
`poetry add python-whois`

## Usage Notes

- Handles common WHOIS lookup errors (e.g., domain not found, rate limits).
- Attempts to parse common WHOIS fields into a structured output.
- Includes the raw WHOIS text in the output if available. 