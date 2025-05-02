# Check usage (optional but good practice)
# assert result.usage.total_tokens > 0  # TestModel generates some usage
# assert result.usage.completion_tokens > 0
# assert result.usage.prompt_tokens > 0


@pytest.mark.asyncio
async def test_domain_analyzer_agent_partial_failure():
    """Test the agent when some tools return None or empty data."""
    # Configure TestModel to simulate a final output reflecting partial data.
    # Note: TestModel doesn't easily simulate intermediate tool *failures*
    # or specific None returns mid-run. FunctionModel is better suited for that.
    # Here, we just define the expected *final* output structure assuming
    # the agent's logic handles potential Nones from (unsimulated) tool calls.
    test_model_partial = TestModel(
        custom_output_args={
            "domain": MOCK_DOMAIN,
            "ip_info": None,
            "shodan_info": None,
            "vt_analysis": {"url": f"http://{MOCK_DOMAIN}", "malicious_count": None},
            "certificates": [],
            "dns_security": {"dnssec_enabled": False},
            "email_security": {
                "spf_record": None,
                "spf_valid": None,
                "dmarc_record": None,
                "dmarc_policy": None,
                "dmarc_valid": None,
            },
            "analysis_summary": (
                "Partial analysis for testdomain.com. IP lookup failed. "
                "VT report might be incomplete. No certificates found. DNSSEC is not enabled. "
                "No email security records found."
            ),
        },
    )

    with domain_analyzer_agent.override(model=test_model_partial):
        # Still run the agent via the user prompt method
        result = await domain_analyzer_agent.run(f"Analyze the domain: {MOCK_DOMAIN}")

    # Assertions for partial failure
    assert isinstance(result.output, DomainAnalysisResult)
    assert result.output.domain == MOCK_DOMAIN
    assert result.output.ip_info is None
    assert result.output.shodan_info is None  # Check Shodan
    assert isinstance(result.output.vt_analysis, VirusTotalUrlAnalysis)  # Check VT
    assert result.output.vt_analysis.malicious_count is None  # VT fields should be None
    assert result.output.certificates == []
    assert result.output.dns_security.dnssec_enabled is False
    assert result.output.email_security.spf_record is None
    assert result.output.email_security.dmarc_record is None
    assert "Partial analysis" in result.output.analysis_summary

    # Check usage (optional but good practice)
    # assert result.usage.total_tokens > 0  # TestModel generates some usage
    # assert result.usage.completion_tokens > 0
    # assert result.usage.prompt_tokens > 0 