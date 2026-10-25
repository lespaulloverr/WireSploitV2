import asyncio
import sys
import os
from pathlib import Path
from unittest.mock import patch

# Add the root directory to sys so we can import engine modules
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import pytest
from engine import tooling
from engine import engine as investigation_engine

# Platform-independent test commands
# Use Python executable with -c for simple commands that work on all platforms
PYTHON_EXE = sys.executable
ECHO_CMD = [PYTHON_EXE, "-c", "print('hello world')"]
SLEEP_CMD = [PYTHON_EXE, "-c", "import time; time.sleep(2)"]


@pytest.mark.asyncio
async def test_tool_command_returns_correct_args():
    """Test that tool_command returns the expected argument list for various CLI tools."""
    test_cases = [
        ("sherlock", "testuser", ["sherlock", "--", "testuser"]),
        ("maigret", "testuser", ["maigret", "--", "testuser"]),
        ("blackbird", "testuser", ["blackbird", "testuser"]),
        ("gosherlock", "testuser", ["gosherlock", "--", "testuser"]),
        ("socialanalyzer", "testuser", ["socialanalyzer", "-u", "--", "testuser"]),
        ("subfinder", "example.com", ["subfinder", "-d", "--", "example.com"]),
        ("assetfinder", "example.com", ["assetfinder", "--", "example.com"]),
        ("amass", "example.com", ["amass", "enum", "-d", "--", "example.com"]),
        ("theharvester", "example.com", ["theharvester", "-d", "--", "example.com", "-b", "baidu,bing,google,yahoo"]),
        ("waymore", "example.com", ["waymore", "-i", "--", "example.com"]),
        ("gau", "example.com", ["gau", "--", "example.com"]),
        ("waybackurls", "example.com", ["waybackurls", "--", "example.com"]),
        ("findomain", "example.com", ["findomain", "-t", "--", "example.com"]),
    ]
    for pid, target, expected_args in test_cases:
        cat = "username" if pid in ["sherlock", "maigret", "blackbird", "gosherlock", "socialanalyzer"] else "domain"
        cmd = tooling.tool_command(pid, target, cat)
        assert cmd is not None, f"tool_command returned None for {pid}"
        assert len(cmd) == 2, f"tool_command did not return length 2 list for {pid}"
        assert cmd[0] == expected_args, f"Expected args {expected_args} for {pid}, got {cmd[0]}"
        assert cmd[1] == "", f"Working directory should be empty string for {pid}, got '{cmd[1]}'"


def test_tool_command_returns_none_for_unknown_tool():
    """Test that tool_command returns None for an unknown tool ID."""
    cmd = tooling.tool_command("unknown_tool", "test", "username")
    assert cmd is None


def test_tool_command_validates_target():
    """Test that tool_command rejects invalid targets."""
    # Empty target
    cmd = tooling.tool_command("sherlock", "", "username")
    assert cmd is None

    # Target with shell metacharacters
    cmd = tooling.tool_command("sherlock", "test; rm -rf /", "username")
    assert cmd is None

    # Target with newlines
    cmd = tooling.tool_command("sherlock", "test\ninjection", "username")
    assert cmd is None

    # Target too long
    cmd = tooling.tool_command("sherlock", "a" * 300, "username")
    assert cmd is None


@pytest.mark.asyncio
async def test_run_subprocess_executes_command_and_returns_output():
    """Test that run_subprocess runs a command and returns the expected output."""
    # Use Python echo command which works on all platforms
    exit_code, stdout, stderr = await tooling.run_subprocess(ECHO_CMD, "", timeout=30)
    assert exit_code == 0
    assert stdout.strip() == "hello world"
    assert stderr == ""


@pytest.mark.asyncio
async def test_run_subprocess_handles_timeout():
    """Test that run_subprocess handles a command that times out."""
    # Use Python sleep command which works on all platforms
    exit_code, stdout, stderr = await tooling.run_subprocess(SLEEP_CMD, "", timeout=1)
    # When timeout occurs, we expect exit code 1, empty stdout, and a stderr indicating timeout
    assert exit_code == 1
    assert stdout == ""
    assert "timeout" in stderr.lower()




@pytest.mark.asyncio
async def test_provider_invokes_cli_tool_correctly():
    """Test that the provider function correctly invokes a CLI tool and uses the parsing function."""
    # We'll test with sherlock as an example
    pid = "sherlock"
    target = "testuser"
    cat = "username"
    srm = False

    # We'll mock asyncio.create_subprocess_exec to return a predefined output
    async def mock_create_subprocess_exec(*args, **kwargs):
        # Create a mock process
        class MockProcess:
            def __init__(self):
                self.returncode = 0
            async def communicate(self, input=None):
                # Return some fake output
                return (b"user1\nuser2\nuser3\n", b"")
        return MockProcess()

    with patch("asyncio.create_subprocess_exec", new=mock_create_subprocess_exec):
        # Call the provider function
        result = await investigation_engine.provider(pid, cat, target, srm)
        # We expect the provider to have called tool_command and run_subprocess
        # and then parse_username_output
        # We'll check that the result is a list of findings from the parsing function
        assert isinstance(result, list)
        # We expect three findings (from the three lines in the mock output)
        assert len(result) == 3
        for finding in result:
            assert finding["entity_key"].startswith("username:sherlock:")
            assert finding["platform"] == "sherlock"
            assert finding["value"] in ["user1", "user2", "user3"]
            assert finding["url"] == ""
            assert finding["source_tools"] == ["sherlock"]
            assert finding["evidence"]["exact_match"] == True
            assert "source" in finding["evidence"]
            assert "raw_output_snippet" in finding["evidence"]


@pytest.mark.asyncio
async def test_provider_handles_tool_not_found():
    """Test that the provider function handles a tool that is not found (tool_command returns None)."""
    # We'll use a CLI tool that we don't have a spec for, but we can also test by making tool_command return None
    # We'll patch tooling.tool_command to return None for a specific pid
    with patch("engine.tooling.tool_command", return_value=None):
        result = await investigation_engine.provider("unknown_cli", "username", "testuser", False)
        # The provider should return an empty list when tool_command returns None
        assert result == []


@pytest.mark.asyncio
async def test_provider_handles_subprocess_error():
    """Test that the provider function handles errors from run_subprocess."""
    # We'll mock run_subprocess to return a non-zero exit code and no output
    with patch("engine.tooling.run_subprocess", return_value=(1, "", "error")):
        # The provider should raise a RuntimeError when code != 0 and not out
        with pytest.raises(RuntimeError):
            await investigation_engine.provider("sherlock", "username", "testuser", False)


@pytest.mark.asyncio
async def test_provider_handles_empty_output():
    """Test that the provider function handles empty output from the tool."""
    # We'll mock run_subprocess to return exit code 0 but empty stdout
    with patch("engine.tooling.run_subprocess", return_value=(0, "", "")):
        result = await investigation_engine.provider("sherlock", "username", "testuser", False)
        # The provider should return an empty list when code == 0 but not out (since the condition is: if code!=0 and not out)
        # Actually, the engine does: if code!=0 and not out: raise RuntimeError(...)
        # So if code==0 and not out, it will not raise an error and will proceed to parsing.
        # The parsing functions will return an empty list if there are no lines.
        assert result == []


@pytest.mark.asyncio
async def test_parse_functions_handle_output():
    """Test that the parsing functions correctly parse sample output."""
    # Test parse_username_output
    output = "alice\nbob\ncharlie\n"
    result = tooling.parse_username_output("sherlock", "testuser", output, "username")
    assert len(result) == 3
    assert result[0]["entity_key"] == "username:sherlock:alice"
    assert result[0]["value"] == "alice"
    assert result[1]["entity_key"] == "username:sherlock:bob"
    assert result[1]["value"] == "bob"
    assert result[2]["entity_key"] == "username:sherlock:charlie"
    assert result[2]["value"] == "charlie"

    # Test parse_domain_lines
    output = "example.com\nsub.example.com\n"
    result = tooling.parse_domain_lines("subfinder", "testuser", output, "domain")
    assert len(result) == 2
    assert result[0]["entity_key"] == "domain:subfinder:example.com"
    assert result[0]["value"] == "example.com"
    assert result[1]["entity_key"] == "domain:subfinder:sub.example.com"
    assert result[1]["value"] == "sub.example.com"

    # Test parse_kv_output
    output = "key1: value1\nkey2: value2\nkey1: value3\nsingle_line"
    result = tooling.parse_kv_output("amass", "testuser", output, "domain")
    # We expect three findings: key1, key2, single_line (since key1 appears twice, we take the first)
    assert len(result) == 3
    assert result[0]["entity_key"] == "kv:amass:key1"
    assert result[0]["value"] == "value1"
    assert result[1]["entity_key"] == "kv:amass:key2"
    assert result[1]["value"] == "value2"
    assert result[2]["entity_key"] == "kv:amass:single_line"
    assert result[2]["value"] == "single_line"


if __name__ == "__main__":
    pytest.main(["-v", __file__])