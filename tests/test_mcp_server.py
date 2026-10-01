"""Tests for `spoofguard/mcp_server.py` — the MCP stdio server.

No test touches the real network. `spoofguard/mcp_server.py` is driven as a
real subprocess over real stdin/stdout pipes (so this exercises the actual
newline-delimited JSON-RPC wire protocol, not an in-process shortcut); DNS
is replaced by a fixture file passed via the SPOOFGUARD_MCP_TEST_FIXTURE
environment variable (see mcp_server.py's `_load_fixture_fetch()`), in the
same `name|TYPE` -> records shape tests/test_scanner.py's own `make_fetch()`
helper uses.
"""

import json
import os
import selectors
import subprocess
import sys
import tempfile
import unittest

_PY = sys.executable
_RECV_TIMEOUT = 5.0


class MCPProcess:
    """Spawns `python -m spoofguard.mcp_server` and drives it over real
    stdin/stdout pipes."""

    def __init__(self, fixture=None):
        env = dict(os.environ)
        self._fixture_path = None
        if fixture is not None:
            fh = tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False, encoding="utf-8")
            json.dump(fixture, fh)
            fh.close()
            self._fixture_path = fh.name
            env["SPOOFGUARD_MCP_TEST_FIXTURE"] = fh.name
        else:
            env.pop("SPOOFGUARD_MCP_TEST_FIXTURE", None)
        self.proc = subprocess.Popen(
            [_PY, "-m", "spoofguard.mcp_server"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
            env=env,
        )

    def send(self, obj) -> None:
        self.proc.stdin.write(json.dumps(obj) + "\n")
        self.proc.stdin.flush()

    def send_raw(self, line: str) -> None:
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()

    def recv(self, timeout: float = _RECV_TIMEOUT):
        """Read and parse one line from stdout, or return None if nothing
        arrives within `timeout` seconds — used to assert that a
        notification produced no response line at all."""
        sel = selectors.DefaultSelector()
        sel.register(self.proc.stdout, selectors.EVENT_READ)
        try:
            events = sel.select(timeout)
        finally:
            sel.close()
        if not events:
            return None
        line = self.proc.stdout.readline()
        if not line:
            return None
        return json.loads(line)

    def initialize(self, protocol_version: str = "2025-06-18"):
        self.send({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": protocol_version,
                "capabilities": {},
                "clientInfo": {"name": "test-client", "version": "0.0.1"},
            },
        })
        resp = self.recv()
        self.send_notification("notifications/initialized")
        return resp

    def send_notification(self, method: str, params=None) -> None:
        obj = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            obj["params"] = params
        self.send(obj)

    def list_tools(self, id_=2):
        self.send({"jsonrpc": "2.0", "id": id_, "method": "tools/list", "params": {}})
        return self.recv()

    def call_tool(self, name: str, arguments=None, id_=2):
        self.send({
            "jsonrpc": "2.0", "id": id_, "method": "tools/call",
            "params": {"name": name, "arguments": arguments if arguments is not None else {}},
        })
        return self.recv()

    def close(self) -> None:
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()
            self.proc.wait()
        try:
            self.proc.stdout.close()
        except Exception:
            pass
        if self._fixture_path:
            try:
                os.unlink(self._fixture_path)
            except OSError:
                pass


# A strong domain, same shape as tests/test_scanner.py::TestStrongDomain.
_GOOD_RECORDS = {
    "good.com|TXT": ["v=spf1 include:_spf.google.com -all"],
    "_dmarc.good.com|TXT": ["v=DMARC1; p=reject; rua=mailto:a@good.com"],
    "default._domainkey.good.com|TXT": ["v=DKIM1; k=rsa; p=MIGf..."],
    "good.com|DS": ["12345 8 2 ABCDEF"],
    "good.com|MX": ["10 aspmx.l.google.com."],
}

# A wide-open domain: nothing published anywhere.
_BAD_RECORDS = {}


class _MCPTestCase(unittest.TestCase):
    """Base class: spawns one MCPProcess per test, closed in tearDown."""

    fixture = {"records": {}, "fail": []}

    def setUp(self):
        self.mcp = MCPProcess(fixture=self.fixture)
        self.addCleanup(self.mcp.close)


class TestInitializeHandshake(_MCPTestCase):
    def test_initialize_returns_protocol_version_and_server_info(self):
        resp = self.mcp.initialize()
        self.assertNotIn("error", resp)
        result = resp["result"]
        self.assertEqual(result["protocolVersion"], "2025-06-18")
        self.assertIn("tools", result["capabilities"])
        self.assertEqual(result["serverInfo"]["name"], "spoofguard-mcp")
        self.assertIn("instructions", result)

    def test_requested_supported_version_is_echoed_back(self):
        resp = self.mcp.initialize(protocol_version="2024-11-05")
        self.assertEqual(resp["result"]["protocolVersion"], "2024-11-05")

    def test_unsupported_protocol_version_falls_back_to_default(self):
        resp = self.mcp.initialize(protocol_version="1900-01-01")
        self.assertEqual(resp["result"]["protocolVersion"], "2025-06-18")


class TestToolsList(_MCPTestCase):
    def test_lists_exactly_three_tools_with_schemas(self):
        self.mcp.initialize()
        resp = self.mcp.list_tools()
        tools = {t["name"]: t for t in resp["result"]["tools"]}
        self.assertEqual(set(tools), {"check_domain", "check_domains", "explain_finding"})
        for t in tools.values():
            self.assertEqual(t["inputSchema"]["type"], "object")
            self.assertIn("required", t["inputSchema"])
            self.assertIn("outputSchema", t)

    def test_check_domain_schema_requires_domain(self):
        self.mcp.initialize()
        resp = self.mcp.list_tools()
        tools = {t["name"]: t for t in resp["result"]["tools"]}
        self.assertEqual(tools["check_domain"]["inputSchema"]["required"], ["domain"])

    def test_check_domains_schema_caps_at_25(self):
        self.mcp.initialize()
        resp = self.mcp.list_tools()
        tools = {t["name"]: t for t in resp["result"]["tools"]}
        self.assertEqual(tools["check_domains"]["inputSchema"]["properties"]["domains"]["maxItems"], 25)


class TestCheckDomainHappyPath(_MCPTestCase):
    fixture = {"records": _GOOD_RECORDS, "fail": []}

    def test_strong_domain_grades_a_with_structured_and_text_content(self):
        self.mcp.initialize()
        resp = self.mcp.call_tool("check_domain", {"domain": "good.com"})
        result = resp["result"]
        self.assertFalse(result["isError"])
        self.assertEqual(result["structuredContent"]["grade"], "A — strong")
        self.assertEqual(result["structuredContent"]["domain"], "good.com")
        self.assertIn("good.com", result["content"][0]["text"])
        statuses = {f["check"]: f["status"] for f in result["structuredContent"]["findings"]}
        self.assertEqual(statuses["SPF"], "PASS")
        self.assertEqual(statuses["DMARC"], "PASS")

    def test_domain_is_normalised_like_the_scanner(self):
        self.mcp.initialize()
        resp = self.mcp.call_tool("check_domain", {"domain": "  Good.COM.  "})
        self.assertEqual(resp["result"]["structuredContent"]["domain"], "good.com")

    def test_unicode_domain_is_idna_encoded(self):
        self.mcp.initialize()
        resp = self.mcp.call_tool("check_domain", {"domain": "münchen.de"})
        # No fixture records for the punycode form -> a legitimate "everything
        # absent" scan, not a validation error; proves the IDNA conversion ran.
        result = resp["result"]
        self.assertFalse(result["isError"])
        self.assertEqual(result["structuredContent"]["domain"], "xn--mnchen-3ya.de")


class TestCheckDomainUnknownOnResolverFailure(_MCPTestCase):
    fixture = {"records": {}, "fail": ["flaky.com|TXT"]}

    def test_lookup_failure_grades_unknown_not_fail_and_is_not_a_tool_error(self):
        self.mcp.initialize()
        resp = self.mcp.call_tool("check_domain", {"domain": "flaky.com"})
        result = resp["result"]
        self.assertFalse(result["isError"])  # UNKNOWN is a valid result, not a tool failure
        self.assertTrue(result["structuredContent"]["grade"].startswith("UNKNOWN"))
        spf = next(f for f in result["structuredContent"]["findings"] if f["check"] == "SPF")
        self.assertEqual(spf["status"], "UNKNOWN")


class TestInvalidDomainRejection(_MCPTestCase):
    def test_url_is_rejected_as_tool_error(self):
        self.mcp.initialize()
        resp = self.mcp.call_tool("check_domain", {"domain": "https://example.com/path"})
        result = resp["result"]
        self.assertTrue(result["isError"])
        self.assertIn("Invalid domain", result["content"][0]["text"])

    def test_ipv4_is_rejected_as_tool_error(self):
        self.mcp.initialize()
        resp = self.mcp.call_tool("check_domain", {"domain": "192.168.1.1"})
        result = resp["result"]
        self.assertTrue(result["isError"])

    def test_ipv6_is_rejected_as_tool_error(self):
        self.mcp.initialize()
        resp = self.mcp.call_tool("check_domain", {"domain": "::1"})
        self.assertTrue(resp["result"]["isError"])

    def test_overlong_label_is_rejected(self):
        self.mcp.initialize()
        resp = self.mcp.call_tool("check_domain", {"domain": ("a" * 64) + ".com"})
        self.assertTrue(resp["result"]["isError"])

    def test_missing_domain_argument_is_a_protocol_error(self):
        self.mcp.initialize()
        resp = self.mcp.call_tool("check_domain", {})
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32602)

    def test_non_string_domain_is_a_protocol_error(self):
        self.mcp.initialize()
        resp = self.mcp.call_tool("check_domain", {"domain": 12345})
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32602)


class TestBatchCap(_MCPTestCase):
    fixture = {"records": {**_GOOD_RECORDS}, "fail": []}

    def test_over_cap_batch_is_a_tool_error(self):
        self.mcp.initialize()
        domains = [f"d{i}.example.com" for i in range(30)]
        resp = self.mcp.call_tool("check_domains", {"domains": domains})
        result = resp["result"]
        self.assertTrue(result["isError"])
        self.assertIn("25", result["content"][0]["text"])

    def test_at_cap_batch_is_accepted(self):
        self.mcp.initialize()
        domains = ["good.com"] + [f"d{i}.example.com" for i in range(24)]
        resp = self.mcp.call_tool("check_domains", {"domains": domains})
        result = resp["result"]
        self.assertFalse(result["isError"])
        self.assertEqual(len(result["structuredContent"]["results"]), 25)

    def test_batch_sorts_most_exposed_first_and_reports_invalid_entries(self):
        self.mcp.initialize()
        resp = self.mcp.call_tool(
            "check_domains",
            {"domains": ["good.com", "wide-open.example.com", "http://bad-url.com"]},
        )
        result = resp["result"]
        self.assertFalse(result["isError"])
        domains_in_order = [r["domain"] for r in result["structuredContent"]["results"]]
        self.assertEqual(domains_in_order[-1], "good.com")  # least exposed last
        self.assertEqual(len(result["structuredContent"]["invalid"]), 1)
        self.assertEqual(result["structuredContent"]["invalid"][0]["domain"], "http://bad-url.com")


class TestExplainFinding(_MCPTestCase):
    def test_explain_check_only(self):
        self.mcp.initialize()
        resp = self.mcp.call_tool("explain_finding", {"check": "SPF"})
        result = resp["result"]
        self.assertFalse(result["isError"])
        self.assertEqual(result["structuredContent"]["check"], "SPF")
        self.assertIsNone(result["structuredContent"]["status"])
        self.assertTrue(len(result["content"][0]["text"]) > 10)

    def test_explain_check_and_status(self):
        self.mcp.initialize()
        resp = self.mcp.call_tool("explain_finding", {"check": "DMARC", "status": "FAIL"})
        result = resp["result"]
        self.assertFalse(result["isError"])
        self.assertEqual(result["structuredContent"]["status"], "FAIL")
        self.assertIn("spoofing gap", result["content"][0]["text"])

    def test_explain_unknown_status_names_the_never_fail_rule(self):
        self.mcp.initialize()
        resp = self.mcp.call_tool("explain_finding", {"check": "SPF", "status": "UNKNOWN"})
        result = resp["result"]
        self.assertFalse(result["isError"])
        self.assertIn("never", result["content"][0]["text"].lower())

    def test_unknown_check_is_a_tool_error(self):
        self.mcp.initialize()
        resp = self.mcp.call_tool("explain_finding", {"check": "NOT_A_REAL_CHECK"})
        self.assertTrue(resp["result"]["isError"])

    def test_missing_check_argument_is_a_protocol_error(self):
        self.mcp.initialize()
        resp = self.mcp.call_tool("explain_finding", {})
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32602)


class TestUnknownTool(_MCPTestCase):
    def test_unknown_tool_name_is_invalid_params(self):
        self.mcp.initialize()
        resp = self.mcp.call_tool("not_a_real_tool", {})
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32602)
        self.assertIn("Unknown tool", resp["error"]["message"])


class TestUnknownMethod(_MCPTestCase):
    def test_unknown_method_is_method_not_found(self):
        self.mcp.initialize()
        self.mcp.send({"jsonrpc": "2.0", "id": 99, "method": "totally/not/a/method", "params": {}})
        resp = self.mcp.recv()
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32601)


class TestMalformedJSON(_MCPTestCase):
    def test_malformed_json_line_is_parse_error(self):
        self.mcp.initialize()
        self.mcp.send_raw("{this is not valid json")
        resp = self.mcp.recv()
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32700)
        self.assertIsNone(resp["id"])


class TestNotificationsGetNoResponse(_MCPTestCase):
    def test_initialized_notification_produces_no_response_line(self):
        self.mcp.send({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "t", "version": "1"}},
        })
        self.mcp.recv()  # the initialize response itself
        self.mcp.send_notification("notifications/initialized")
        # Nothing should arrive for the notification before the next real
        # request's response does.
        resp = self.mcp.recv(timeout=0.5)
        self.assertIsNone(resp)

    def test_notification_does_not_desync_subsequent_requests(self):
        self.mcp.initialize()
        self.mcp.send_notification("notifications/some_unknown_thing")
        resp = self.mcp.list_tools(id_=42)
        self.assertEqual(resp["id"], 42)
        self.assertIn("result", resp)

    def test_arbitrary_notification_with_no_id_gets_no_response(self):
        self.mcp.initialize()
        self.mcp.send({"jsonrpc": "2.0", "method": "notifications/cancelled",
                        "params": {"requestId": 1}})
        resp = self.mcp.recv(timeout=0.5)
        self.assertIsNone(resp)


if __name__ == "__main__":
    unittest.main()
