"""Tests for TerminalGateway, dot command parsing, and output pagination."""

from pathlib import Path

from src.executor.terminals import (
    MAX_TERMINALS,
    TerminalGateway,
    TerminalState,
    paginate_output,
    parse_dot_command,
)


def test_parse_dot_commands():
    # Stop command
    assert parse_dot_command(".stop") == ("stop", [])
    assert parse_dot_command("  .stop  ") == ("stop", [])

    # New terminal commands
    assert parse_dot_command(".new") == ("new", [])
    assert parse_dot_command(".newterminal") == ("new", [])
    assert parse_dot_command(".n") == ("new", [])

    # Switch terminal
    assert parse_dot_command(".t1") == ("switch", ["1"])
    assert parse_dot_command(".t10") == ("switch", ["10"])
    assert parse_dot_command(".terminal3") == ("switch", ["3"])
    assert parse_dot_command(".t 4") == ("switch", ["4"])

    # List terminals
    assert parse_dot_command(".terminals") == ("list", [])
    assert parse_dot_command(".list") == ("list", [])

    # Close terminal
    assert parse_dot_command(".close") == ("close", [])
    assert parse_dot_command(".close2") == ("close", ["2"])
    assert parse_dot_command(".close 5") == ("close", ["5"])

    # Non-dot commands return None
    assert parse_dot_command("/run ls") is None
    assert parse_dot_command("uptime") is None
    assert parse_dot_command("") is None


def test_terminal_gateway_lifecycle(tmp_path: Path):
    gw = TerminalGateway(user_id=1001, default_work_dir=tmp_path)

    # Initial state: Terminal 1 active
    t1 = gw.get_active_terminal()
    assert t1.terminal_id == 1
    assert t1.state == TerminalState.IDLE
    assert gw.active_terminal_id == 1

    # Switch to terminal 2
    success, msg = gw.switch_terminal(2)
    assert success is True
    assert "Terminal #2" in msg
    assert gw.active_terminal_id == 2
    assert 2 in gw.terminals

    # Open new terminal (should allocate 3)
    success, new_id, msg = gw.open_new_terminal()
    assert success is True
    assert new_id == 3
    assert gw.active_terminal_id == 3

    # List terminals
    listing = gw.list_terminals()
    assert len(listing) == 3
    assert any(item["id"] == 3 and item["is_active"] for item in listing)

    # Close terminal 3
    success, msg = gw.close_terminal(3)
    assert success is True
    assert 3 not in gw.terminals
    assert gw.active_terminal_id in (1, 2)


def test_terminal_gateway_max_limit(tmp_path: Path):
    gw = TerminalGateway(user_id=1001, default_work_dir=tmp_path)

    # Open all 10 terminals
    for _ in range(MAX_TERMINALS - 1):
        success, _, _ = gw.open_new_terminal()
        assert success is True

    assert len(gw.terminals) == 10

    # 11th terminal rejected
    success, _, msg = gw.open_new_terminal()
    assert success is False
    assert "giới hạn tối đa" in msg


def test_terminal_stop_request(tmp_path: Path):
    gw = TerminalGateway(user_id=1001, default_work_dir=tmp_path)
    t = gw.get_active_terminal()
    t.state = TerminalState.RUNNING

    assert t.request_stop() is False  # No process attached yet
    assert t.stop_requested is True
    assert t.state == TerminalState.STOPPED


def test_paginate_output():
    # Empty output
    empty_res = paginate_output("")
    assert len(empty_res) == 1
    assert "Không có dữ liệu" in empty_res[0]

    # Small output (< 3500 chars)
    small_text = "Hello world\nLine 2"
    small_res = paginate_output(small_text, max_chunk_chars=3500)
    assert len(small_res) == 1
    assert "<pre><code class='language-text'>Hello world\nLine 2</code></pre>" in small_res[0]

    # Large output (> 10000 chars)
    large_text = "\n".join(f"Line {i}: output data line" for i in range(500))
    chunks = paginate_output(large_text, max_chunk_chars=1000)
    assert len(chunks) > 1

    # Chunk 1 has suffix [Còn tiếp...]
    assert "Còn tiếp" in chunks[0]
    # Chunk 2 has prefix [Tiếp tục phần trước...]
    assert "Tiếp tục phần trước" in chunks[1]

    # HTML escaping check
    html_text = "<script>alert('xss')</script> & \"quotes\""
    html_res = paginate_output(html_text)
    assert "<script>" not in html_res[0]
    assert "&lt;script&gt;" in html_res[0]
    assert "&amp;" in html_res[0]
