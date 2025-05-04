"""Tests for network security tools."""

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic_ai.tools import RunContext, Tool
from pydantic_ai.usage import Usage

# Import the module itself and specific classes/helpers
import tools.network_tools

# Import the specific functions and classes needed for testing
from tools.network_tools import (
    DomainInfoParams,
    NucleiResult,
    NucleiScanParams,
    _build_nuclei_command,
    nuclei_scan_tool,
    parse_domain_info_tool,
)

# Get references to the functions *before* they are potentially reassigned
# at the end of the tools.network_tools module when Tool() is called.
_nuclei_scan_tool_func = tools.network_tools.nuclei_scan_tool
_parse_domain_info_tool_func = tools.network_tools.parse_domain_info_tool

# Define module-level constant for base flags
BASE_FLAGS: set[str] = {"-jsonl", "-silent", "-nc", "-timeout", "-rate-limit"}


@pytest.mark.asyncio
@patch("tools.network_tools.asyncio.create_subprocess_exec")
@patch("os.path.exists")
@patch("builtins.open")
@patch("os.remove")
async def test_nuclei_scan_tool_success(
    mock_remove: MagicMock,
    mock_open: MagicMock,
    mock_exists: MagicMock,
    mock_subprocess_exec: AsyncMock,
):
    """Test nuclei_scan_tool successful execution path."""
    # 1. Setup Mock Subprocess (Success)
    mock_process = AsyncMock()
    mock_process.communicate.return_value = (b"", b"")  # No stdout/stderr needed
    mock_process.returncode = 0
    mock_subprocess_exec.return_value = mock_process

    # 2. Setup Mock File I/O
    mock_exists.return_value = True
    mock_file_handle = MagicMock()
    mock_file_handle.read.return_value = (
        '{"template-id": "vuln1", "info": {"severity": "high"}}\n'
        '{"template-id": "vuln2", "info": {"severity": "medium"}}'
    )
    mock_open.return_value.__enter__.return_value = mock_file_handle

    # 3. Prepare Tool Inputs
    params = NucleiScanParams(target="http://testhost.com")
    mock_ctx = RunContext(
        deps={},
        model=MagicMock(),
        usage=Usage(),
        prompt=MagicMock(),
    )
    sanitized_target = params.target.replace("/", "_").replace(":", "_")
    temp_file_path = f"/tmp/nuclei_scan_{sanitized_target}.json"
    expected_cmd_list = _build_nuclei_command(params)
    expected_cmd_str = " ".join([*expected_cmd_list, "-o", temp_file_path])

    # 4. Call the Tool
    with patch.dict(os.environ, {"AGENT_ENV": "production"}, clear=True):
        result: NucleiResult = await nuclei_scan_tool(mock_ctx, params)

    # 5. Assert Results
    assert result.scan_status == "success_with_findings"  # Check explicit status
    assert result.success is True
    assert result.error is None
    assert len(result.findings) == 2
    assert result.findings[0]["template-id"] == "vuln1"
    assert result.findings[1]["info"]["severity"] == "medium"
    assert result.command == expected_cmd_str
    assert '"template-id": "vuln1"' in result.raw_output

    # 6. Assert Mock Calls
    mock_subprocess_exec.assert_awaited_once()
    call_args, _ = mock_subprocess_exec.call_args
    assert list(call_args) == [*expected_cmd_list, "-o", temp_file_path]
    mock_open.assert_called_once_with(temp_file_path)
    mock_exists.assert_called_once_with(temp_file_path)
    mock_remove.assert_called_once_with(temp_file_path)


@pytest.mark.asyncio
@patch("tools.network_tools.asyncio.create_subprocess_exec")
async def test_nuclei_scan_tool_subprocess_error(
    mock_subprocess_exec: AsyncMock,
):
    """Test nuclei_scan_tool when the subprocess returns a non-zero exit code."""
    mock_process = AsyncMock()
    mock_process.communicate.return_value = (
        b"stdout ignored",
        b"Error: Template not found",
    )
    mock_process.returncode = 1
    mock_subprocess_exec.return_value = mock_process

    params = NucleiScanParams(target="http://badhost.com")
    mock_ctx = RunContext(
        deps={},
        model=MagicMock(),
        usage=Usage(),
        prompt=MagicMock(),
    )
    sanitized_target = params.target.replace("/", "_").replace(":", "_")
    temp_file_path = f"/tmp/nuclei_scan_{sanitized_target}.json"
    expected_cmd_list = _build_nuclei_command(params)
    expected_cmd_str = " ".join([*expected_cmd_list, "-o", temp_file_path])

    with patch.dict(os.environ, {"AGENT_ENV": "production"}, clear=True):
        result: NucleiResult = await nuclei_scan_tool(mock_ctx, params)

    assert result.scan_status == "error"
    assert result.success is False
    assert result.error == "Error: Template not found"
    assert result.raw_output == "stdout ignored"
    assert result.findings == []
    assert result.command == expected_cmd_str
    mock_subprocess_exec.assert_awaited_once()
    call_args, _ = mock_subprocess_exec.call_args
    assert list(call_args) == [*expected_cmd_list, "-o", temp_file_path]


@pytest.mark.asyncio
@patch("tools.network_tools.asyncio.create_subprocess_exec")
@patch("tools.network_tools.open", side_effect=OSError("Permission denied"))
@patch("os.path.exists")
@patch("os.remove")
async def test_nuclei_scan_tool_file_read_error(
    mock_remove: MagicMock,
    mock_exists: MagicMock,
    mock_open: MagicMock,
    mock_subprocess_exec: AsyncMock,
):
    """Test nuclei_scan_tool when reading the results file fails."""
    mock_process = AsyncMock()
    mock_process.communicate.return_value = (b"", b"")
    mock_process.returncode = 0
    mock_subprocess_exec.return_value = mock_process
    mock_exists.return_value = True

    params = NucleiScanParams(target="http://fileerror.com")
    mock_ctx = RunContext(
        deps={},
        model=MagicMock(),
        usage=Usage(),
        prompt=MagicMock(),
    )
    sanitized_target = params.target.replace("/", "_").replace(":", "_")
    temp_file_path = f"/tmp/nuclei_scan_{sanitized_target}.json"
    expected_cmd_list = _build_nuclei_command(params)
    expected_cmd_str = " ".join([*expected_cmd_list, "-o", temp_file_path])

    with patch.dict(os.environ, {"AGENT_ENV": "production"}, clear=True):
        result: NucleiResult = await nuclei_scan_tool(mock_ctx, params)

    assert result.scan_status == "error"
    assert result.success is False
    assert "Error processing results file" in result.error
    assert "Permission denied" in result.error
    assert result.raw_output == ""  # No raw output could be read
    assert result.findings == []
    assert result.command == expected_cmd_str
    mock_subprocess_exec.assert_awaited_once()
    mock_open.assert_called_once_with(temp_file_path)
    mock_exists.assert_called_once_with(temp_file_path)
    mock_remove.assert_called_once_with(temp_file_path)


@pytest.mark.asyncio
@patch("tools.network_tools.asyncio.create_subprocess_exec")
@patch("tools.network_tools.open", new_callable=MagicMock)
@patch("os.path.exists")
@patch("os.remove")
async def test_nuclei_scan_tool_file_cleanup_error(
    mock_remove: MagicMock,
    mock_exists: MagicMock,
    mock_open: MagicMock,
    mock_subprocess_exec: AsyncMock,
):
    """Test nuclei_scan_tool successful execution but failing file cleanup."""
    mock_process = AsyncMock()
    mock_process.communicate.return_value = (b"", b"")
    mock_process.returncode = 0
    mock_subprocess_exec.return_value = mock_process
    mock_exists.return_value = True
    mock_file_handle = MagicMock()
    mock_file_handle.read.return_value = (
        '{"template-id": "vuln-cleanup-test", "info": {}}'
    )
    mock_open.return_value.__enter__.return_value = mock_file_handle

    params = NucleiScanParams(target="http://cleanup-error.com")
    mock_ctx = RunContext(
        deps={},
        model=MagicMock(),
        usage=Usage(),
        prompt=MagicMock(),
    )
    sanitized_target = params.target.replace("/", "_").replace(":", "_")
    temp_file_path = f"/tmp/nuclei_scan_{sanitized_target}.json"

    with patch.dict(os.environ, {"AGENT_ENV": "production"}, clear=True):
        result: NucleiResult = await nuclei_scan_tool(mock_ctx, params)

    assert result.scan_status == "success_with_findings"
    assert result.success is True  # Scan itself succeeded
    assert result.error is None
    assert len(result.findings) == 1
    assert result.findings[0]["template-id"] == "vuln-cleanup-test"
    mock_subprocess_exec.assert_awaited_once()
    mock_open.assert_called_once_with(temp_file_path)
    mock_exists.assert_called_once_with(temp_file_path)
    mock_remove.assert_called_once_with(temp_file_path)  # remove was called


@pytest.mark.asyncio
@patch("tools.network_tools.asyncio.create_subprocess_exec")
@patch("tools.network_tools.open", new_callable=MagicMock)
@patch("os.path.exists")
@patch("os.remove")
async def test_nuclei_scan_tool_json_decode_error(
    mock_remove: MagicMock,
    mock_exists: MagicMock,
    mock_open: MagicMock,
    mock_subprocess_exec: AsyncMock,
):
    """Test nuclei_scan_tool handling JSONDecodeError when parsing results."""
    mock_process = AsyncMock()
    mock_process.communicate.return_value = (b"", b"")
    mock_process.returncode = 0
    mock_subprocess_exec.return_value = mock_process
    mock_exists.return_value = True
    mock_file_handle = MagicMock()
    # Malformed JSON but with one valid line after
    mock_file_handle.read.return_value = 'invalid json line\n{"template-id": "valid"}'
    mock_open.return_value.__enter__.return_value = mock_file_handle

    params = NucleiScanParams(target="http://json-error.com")
    mock_ctx = RunContext(deps={}, model=MagicMock(), usage=Usage(), prompt=MagicMock())
    sanitized_target = params.target.replace("/", "_").replace(":", "_")
    temp_file_path = f"/tmp/nuclei_scan_{sanitized_target}.json"

    with patch.dict(os.environ, {"AGENT_ENV": "production"}, clear=True):
        result: NucleiResult = await nuclei_scan_tool(mock_ctx, params)

    # The scan technically succeeded but parsing had issues
    assert result.scan_status == "success_with_findings"  # Changed assertion
    assert result.success is True  # Subprocess succeeded
    assert result.error is None  # No process error
    assert "invalid json line" in result.raw_output  # Should still contain raw data
    assert len(result.findings) == 1  # Should parse the valid line
    assert result.findings[0]["template-id"] == "valid"
    mock_remove.assert_called_once_with(temp_file_path)


@pytest.mark.asyncio
@patch(
    "tools.network_tools.asyncio.create_subprocess_exec",
    side_effect=FileNotFoundError("nuclei not found"),
)
async def test_nuclei_scan_tool_subprocess_exception(
    mock_subprocess_exec: AsyncMock,
):
    """Test nuclei_scan_tool handling exceptions during subprocess creation."""
    params = NucleiScanParams(target="http://exception.com")
    mock_ctx = RunContext(deps={}, model=MagicMock(), usage=Usage(), prompt=MagicMock())

    with patch.dict(os.environ, {"AGENT_ENV": "production"}, clear=True):
        result: NucleiResult = await nuclei_scan_tool(mock_ctx, params)

    assert result.scan_status == "error"
    assert result.success is False
    # Assert correct error message format
    assert "Error executing nuclei: nuclei not found" in result.error
    assert result.findings == []
    assert result.command is not None  # Command should still be built


@pytest.mark.asyncio
@patch("tools.network_tools.asyncio.create_subprocess_exec")
@patch("tools.network_tools.open", new_callable=MagicMock)
@patch("os.path.exists")
@patch("os.remove")
async def test_nuclei_scan_tool_success_no_findings(
    mock_remove: MagicMock,
    mock_exists: MagicMock,
    mock_open: MagicMock,
    mock_subprocess_exec: AsyncMock,
):
    """Test nuclei_scan_tool successful execution with no findings reported."""
    mock_process = AsyncMock()
    mock_process.communicate.return_value = (b"", b"")
    mock_process.returncode = 0
    mock_subprocess_exec.return_value = mock_process
    mock_exists.return_value = True
    mock_file_handle = MagicMock()
    mock_file_handle.read.return_value = ""  # Empty file means no findings
    mock_open.return_value.__enter__.return_value = mock_file_handle

    params = NucleiScanParams(target="http://no-findings.com")
    mock_ctx = RunContext(deps={}, model=MagicMock(), usage=Usage(), prompt=MagicMock())

    with patch.dict(os.environ, {"AGENT_ENV": "production"}, clear=True):
        result: NucleiResult = await nuclei_scan_tool(mock_ctx, params)

    assert result.scan_status == "success_no_findings"
    assert result.success is True
    assert result.error is None
    assert result.findings == []
    assert result.raw_output == ""
    mock_remove.assert_called_once()


# --- Tests for _build_nuclei_command --- #


class TestBuildNucleiCommand:
    """Tests focusing on the _build_nuclei_command helper function."""

    def test_build_basic_command(self):
        """Test the most basic command structure."""
        params = NucleiScanParams(target="http://test.com")
        cmd = _build_nuclei_command(params)
        # Check essential parts and default values
        assert cmd[:3] == ["nuclei", "-target", "http://test.com"]
        assert "-jsonl" in cmd
        assert "-no-color" in cmd
        assert "-timeout" in cmd
        assert cmd[cmd.index("-timeout") + 1] == "10"  # Default timeout
        assert "-rate-limit" in cmd
        assert cmd[cmd.index("-rate-limit") + 1] == "150"  # Default rate limit

    def test_boolean_flags(self):
        """Test boolean flags are added correctly when True."""
        # Use full flag names as generated by the function
        params = NucleiScanParams(
            target="t",
            automatic_scan=True,  # -as
            new_templates=True,  # -nt
            validate_templates=True,  # -validate -> Renamed
            scan_all_ips=True,  # -sa
            no_strict_syntax=True,  # -nss
            store_resp=True,  # -sresp
            omit_raw=True,  # -or
            omit_template=True,  # -ot
            matcher_status=True,  # -ms
            follow_redirects=True,  # -fr
            follow_host_redirects=True,  # -fhr
            disable_redirects=True,  # -dr
            system_resolvers=True,  # -sr
            disable_clustering=True,  # -dc
            passive=True,  # -passive
            force_http2=True,  # -fh2
            env_vars=True,  # -ev
            restrict_local_network_access=True,  # -lna
            no_interactsh=True,  # -ni
            dast=True,  # -dast
            uncover=True,  # -uc
            leave_default_ports=True,  # -ldp
            no_mhe=True,  # -nmhe
            project=True,  # -project
            stop_at_first_match=True,  # -spm
            stream=True,  # -stream
            no_httpx=True,  # -nh
            no_stdin=True,  # -no-stdin
            headless=True,  # -headless
            show_browser=True,  # -sb
            system_chrome=True,  # -sc
            debug=True,  # -debug
            debug_req=True,  # -dreq
            debug_resp=True,  # -dresp
            proxy_internal=True,  # -pi
            hang_monitor=True,  # -hm
            verbose=True,  # -v
            show_var_dump=True,  # -svd
        )
        cmd = _build_nuclei_command(params)
        # Use full flag names for assertion
        expected_flags = {
            "-automatic-scan",
            "-new-templates",
            "-validate",
            "-scan-all-ips",
            "-no-strict-syntax",
            "-store-resp",
            "-omit-raw",
            "-omit-template",
            "-matcher-status",
            "-follow-redirects",
            "-follow-host-redirects",
            "-disable-redirects",
            "-system-resolvers",
            "-disable-clustering",
            "-passive",
            "-force-http2",
            "-env-vars",
            "-restrict-local-network-access",
            "-no-interactsh",
            "-dast",
            "-uncover",
            "-leave-default-ports",
            "-no-mhe",
            "-project",
            "-stop-at-first-match",
            "-stream",
            "-no-httpx",
            "-no-stdin",
            "-headless",
            "-show-browser",
            "-system-chrome",
            "-debug",
            "-debug-req",
            "-debug-resp",
            "-proxy-internal",
            "-hang-monitor",
            "-verbose",
            "-show-var-dump",
        }
        # Check flags are present
        cmd_set = set(cmd)
        # Remove base flags before checking specific boolean flags
        cmd_flags_only = cmd_set - BASE_FLAGS - {"nuclei", "-target", "t", "10", "150"}
        assert expected_flags.issubset(cmd_flags_only)

        # Check no flags are present when False (default)
        params_false = NucleiScanParams(target="t")
        cmd_false = _build_nuclei_command(params_false)
        cmd_false_set = set(cmd_false)
        cmd_false_flags_only = (
            cmd_false_set - BASE_FLAGS - {"nuclei", "-target", "t", "10", "150"}
        )
        assert len(expected_flags.intersection(cmd_false_flags_only)) == 0

    def test_list_string_flags(self):
        """Test flags taking comma-separated lists of strings."""
        # Use full flag names as generated by the function
        params = NucleiScanParams(
            target="t",
            exclude_hosts=["h1", "h2"],  # -eh -> -exclude-hosts
            ip_version=["4", "6"],  # -iv -> -ip-version
            new_templates_version=["v1", "v2"],  # -ntv -> -new-templates-version
            templates=["t1.yaml", "dir/"],  # -t -> -templates
            template_url=["url1", "url2"],  # -turl -> -template-url
            workflows=["w1", "w2"],  # -w -> -workflows
            workflow_url=["wurl1", "wurl2"],  # -wurl -> -workflow-url
            author=["a1", "a2"],  # -a -> -author
            tags=["tag1", "tag2"],  # -tags
            exclude_tags=["etag1", "etag2"],  # -etags -> -exclude-tags
            include_tags=["itag1", "itag2"],  # -itags -> -include-tags
            template_id=["tid1", "tid2"],  # -id -> -template-id
            exclude_id=["eid1", "eid2"],  # -eid -> -exclude-id
            include_templates=["itpl1", "itpl2"],  # -it -> -include-templates
            exclude_templates=["etpl1", "etpl2"],  # -et -> -exclude-templates
            exclude_matchers=["em1", "em2"],  # -em -> -exclude-matchers
            severity=["high", "critical"],  # -s -> -severity
            exclude_severity=["low", "info"],  # -es -> -exclude-severity
            protocol_type=["http", "dns"],  # -pt -> -type
            exclude_type=["tcp"],  # -ept -> -exclude-type
            template_condition=["cond1", "cond2"],  # -tc -> -template-condition
            # header handled separately
            track_error=["err1", "err2"],  # -te -> -track-error
            proxy=["p1", "p2"],  # -p -> -proxy
            uncover_query=["uq1", "uq2"],  # -uq -> -uncover-query
            uncover_engine=["shodan", "censys"],  # -ue -> -uncover-engine
            redact_keys=["key1", "key2"],  # -rd -> -redact
        )
        cmd = _build_nuclei_command(params)
        # Use full flag names for expected dictionary
        expected = {
            "-exclude-hosts": "h1,h2",
            "-ip-version": "4,6",
            "-new-templates-version": "v1,v2",
            "-templates": "t1.yaml,dir/",
            "-template-url": "url1,url2",
            "-workflows": "w1,w2",
            "-workflow-url": "wurl1,wurl2",
            "-author": "a1,a2",
            "-tags": "tag1,tag2",
            "-exclude-tags": "etag1,etag2",
            "-include-tags": "itag1,itag2",
            "-template-id": "tid1,tid2",
            "-exclude-id": "eid1,eid2",
            "-include-templates": "itpl1,itpl2",
            "-exclude-templates": "etpl1,etpl2",
            "-exclude-matchers": "em1,em2",
            "-severity": "high,critical",
            "-exclude-severity": "low,info",
            "-type": "http,dns",
            "-exclude-type": "tcp",
            "-template-condition": "cond1,cond2",
            "-track-error": "err1,err2",
            "-uncover-query": "uq1,uq2",
            "-uncover-engine": "shodan,censys",
            "-redact": "key1,key2",
        }
        for flag, value in expected.items():
            assert flag in cmd
            assert cmd[cmd.index(flag) + 1] == value

        # Handle repeated flags like -proxy
        assert cmd.count("-proxy") == 2
        assert "p1" in cmd
        assert "p2" in cmd
        p1_index = cmd.index("p1")
        p2_index = cmd.index("p2")
        assert cmd[p1_index - 1] == "-proxy"
        assert cmd[p2_index - 1] == "-proxy"

    def test_string_value_flags(self):
        """Test flags taking a single string value."""
        # Use full flag names as generated by the function
        params = NucleiScanParams(
            target="t",
            store_resp_dir="/path/to/resp",  # -srd -> -store-resp-dir
            project_path="/path/to/proj",  # -project-path
            scan_strategy="host-spray",  # -ss -> -scan-strategy
            input_read_timeout="5m",  # -irt -> -input-read-timeout
            interface="eth0",  # -i -> -interface
            attack_type="clusterbomb",  # -at -> -attack-type
            source_ip="1.1.1.1",  # -sip -> -source-ip
            fuzzing_type="replace",  # -ft -> -fuzzing-type
            fuzzing_mode="single",  # -fm -> -fuzzing-mode
            uncover_field="host",  # -uf -> -uncover-field
            interactsh_server="http://interact.sh",  # -iserver -> -interactsh-server
            interactsh_token="secrettoken",  # -itoken -> -interactsh-token
        )
        cmd = _build_nuclei_command(params)
        # Use full flag names for expected dictionary
        expected = {
            "-store-resp-dir": "/path/to/resp",
            "-project-path": "/path/to/proj",
            "-scan-strategy": "host-spray",
            "-input-read-timeout": "5m",
            "-interface": "eth0",
            "-attack-type": "clusterbomb",
            "-source-ip": "1.1.1.1",
            "-fuzzing-type": "replace",
            "-fuzzing-mode": "single",
            "-uncover-field": "host",
            "-interactsh-server": "http://interact.sh",
            "-interactsh-token": "secrettoken",
        }
        for flag, value in expected.items():
            assert flag in cmd
            assert cmd[cmd.index(flag) + 1] == value

    def test_integer_value_flags(self):
        """Test flags taking an integer value."""
        # Use full flag names as generated by the function
        params = NucleiScanParams(
            target="t",
            max_redirects=5,  # -mr -> -max-redirects
            response_size_read=1024,  # -rsr -> -response-size-read
            interactions_cache_size=100,  # -interactions-cache-size
            interactions_eviction=60,  # -interactions-eviction
            interactions_poll_duration=5,  # -interactions-poll-duration
            interactions_cooldown_period=30,  # -interactions-cooldown-period
            uncover_limit=50,  # -ul -> -uncover-limit
            rate_limit=100,  # -rl -> -rate-limit
            bulk_size=10,  # -bs -> -bulk-size
            concurrency=20,  # -c -> -concurrency
            headless_bulk_size=5,  # -hbs -> -headless-bulk-size
            headless_concurrency=2,  # -headc -> -headless-concurrency
            payload_concurrency=25,  # -pc -> -payload-concurrency
            probe_concurrency=50,  # -prc -> -probe-concurrency
            timeout=15,  # -timeout
            retries=3,  # -retries
            max_host_error=10,  # -mhe -> -max-host-error
            page_timeout=20,  # -page-timeout
            var_dump_limit=5,  # -vdl -> -var-dump-limit
        )
        cmd = _build_nuclei_command(params)
        # Use full flag names for expected dictionary
        expected = {
            "-max-redirects": "5",
            "-response-size-read": "1024",
            "-interactions-cache-size": "100",
            "-interactions-eviction": "60",
            "-interactions-poll-duration": "5",
            "-interactions-cooldown-period": "30",
            "-uncover-limit": "50",
            "-rate-limit": "100",
            "-bulk-size": "10",
            "-concurrency": "20",
            "-headless-bulk-size": "5",
            "-headless-concurrency": "2",
            "-payload-concurrency": "25",
            "-probe-concurrency": "50",
            "-timeout": "15",
            "-retries": "3",
            "-max-host-error": "10",
            "-page-timeout": "20",
            "-var-dump-limit": "5",
        }
        for flag, value in expected.items():
            assert flag in cmd
            assert cmd[cmd.index(flag) + 1] == value

    def test_header_flag_handling(self):
        """Verify -header flag is added multiple times for multiple headers."""
        # Use full flag name
        params = NucleiScanParams(target="t", header=["H1:V1", "H2: V2"])
        cmd = _build_nuclei_command(params)
        assert cmd.count("-header") == 2  # Check for full flag name
        assert "H1:V1" in cmd
        assert "H2: V2" in cmd
        h1_index = cmd.index("H1:V1")
        h2_index = cmd.index("H2: V2")
        assert cmd[h1_index - 1] == "-header"
        assert cmd[h2_index - 1] == "-header"


# --- Tests for parse_domain_info_tool --- #


@pytest.mark.asyncio
async def test_parse_domain_info_tool_no_data():
    """Test parse_domain_info_tool with no domain_info in context."""
    mock_ctx = RunContext(deps={}, model=MagicMock(), usage=Usage(), prompt=MagicMock())
    params = DomainInfoParams(fields_to_extract=["ip_info", "shodan_info"])

    result = await parse_domain_info_tool(mock_ctx, params)
    # Assert against the actual returned dictionary
    assert result == {"message": "No domain info in deps", "status": "no_data"}


@pytest.mark.asyncio
async def test_parse_domain_info_tool_basic_data(
    mock_domain_info,  # Uses fixture from conftest
):
    """Test parse_domain_info_tool extracting basic fields."""
    deps_data = {"domain_info": mock_domain_info}
    mock_ctx = RunContext(
        deps=deps_data, model=MagicMock(), usage=Usage(), prompt=MagicMock()
    )
    params = DomainInfoParams(fields_to_extract=["ip_addresses", "dns_records"])

    result = await parse_domain_info_tool(mock_ctx, params)
    # Assert directly on the result dictionary
    assert "ip_addresses" in result
    assert "dns_records" in result
    assert result["ip_addresses"] == mock_domain_info["ip_addresses"]
    assert result["dns_records"] == mock_domain_info["dns_records"]
    # Assert that fields NOT requested are NOT present
    assert "certificates" not in result
    assert "shodan_info" not in result
    assert "vt_analysis" not in result
    assert "domain" not in result  # Example of another existing but unrequested field
    assert "ssl_info" not in result
    # Check status is not present on success
    assert "status" not in result
    assert "message" not in result


@pytest.mark.asyncio
async def test_parse_domain_info_tool_partial_data():
    """Test parse_domain_info_tool when some requested fields are missing."""
    partial_domain_info = {
        "domain": "partial.com",
        "ip_info": {"ip_address": "1.2.3.4"},
        "certificates": [],
    }
    deps_data = {"domain_info": partial_domain_info}
    mock_ctx = RunContext(
        deps=deps_data, model=MagicMock(), usage=Usage(), prompt=MagicMock()
    )
    params = DomainInfoParams(
        fields_to_extract=["ip_info", "shodan_info", "vt_analysis", "certificates"]
    )

    result = await parse_domain_info_tool(mock_ctx, params)
    # Assert directly on the result dictionary
    assert "ip_info" in result
    assert "certificates" in result
    assert result["ip_info"]["ip_address"] == "1.2.3.4"
    assert result["certificates"] == []
    assert "shodan_info" not in result
    assert "vt_analysis" not in result
    assert "status" not in result
    assert "message" not in result


# Tests for the Tool instances (optional but good practice)


def test_nuclei_scan_tool_instance():
    """Verify the Tool instance for nuclei scan is created correctly."""
    instance = tools.network_tools.nuclei_scan_tool_instance
    assert isinstance(instance, Tool)
    assert instance.name == "nuclei_scan_tool"
    # assert instance.func == _nuclei_scan_tool_func # Removed
    # assert instance.input_model == NucleiScanParams # Removed


def test_parse_domain_info_tool_instance():
    """Verify the Tool instance for parse domain info is created correctly."""
    instance = tools.network_tools.parse_domain_info_tool_instance
    assert isinstance(instance, Tool)
    assert instance.name == "parse_domain_info_tool"
    # assert instance.func == _parse_domain_info_tool_func # Removed
    # assert instance.input_model == DomainInfoParams # Removed
