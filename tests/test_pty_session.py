"""Tests for PTYSessionManager, multi-user terminals, and real prompt capture."""

import pytest

from src.executor.pty_session import PTYSessionManager


@pytest.mark.asyncio
async def test_pty_session_create_switch_and_prompt_format():
    mgr = PTYSessionManager(mock_pty=True)
    user_id = 1001

    # 1. Create Terminal 1 for root
    term1 = await mgr.create_terminal(user_id=user_id, username="root")
    assert term1.terminal_id == 1
    assert term1.username == "root"

    # 2. Check prompt formatting:
    # Terminal1 - dd/mm/yyyy hh:mm:ss
    # root@server:~#
    prompt_banner = mgr.format_terminal_prompt(user_id=user_id, terminal_id=1)
    lines = prompt_banner.strip().split("\n")
    assert len(lines) == 2
    assert lines[0].startswith("Terminal1 - ")
    assert "/" in lines[0] and ":" in lines[0]
    assert "root@" in lines[1]

    # 3. Create Terminal 2 for guest
    term2 = await mgr.create_terminal(user_id=user_id, username="guest")
    assert term2.terminal_id == 2
    assert term2.username == "guest"

    # Active terminal is now 2
    active = mgr.get_active_terminal(user_id)
    assert active.terminal_id == 2
    assert active.username == "guest"

    # 4. Switch back to Terminal 1
    switched, msg = mgr.switch_terminal(user_id=user_id, terminal_id=1)
    assert switched is True
    assert mgr.get_active_terminal(user_id).username == "root"


@pytest.mark.asyncio
async def test_pty_session_send_command_and_prompt_update():
    mgr = PTYSessionManager(mock_pty=True)
    user_id = 1001
    await mgr.create_terminal(user_id=user_id, username="root")

    # Send command
    output, prompt = await mgr.execute_in_active_terminal(user_id=user_id, command="echo 'Hello Linux'")
    assert "Hello Linux" in output
    assert "root@" in prompt


@pytest.mark.asyncio
async def test_pty_session_max_ten_terminals():
    mgr = PTYSessionManager(mock_pty=True)
    user_id = 1001
    # Create 10 terminals
    for i in range(1, 11):
        term = await mgr.create_terminal(user_id=user_id, username=f"user{i}")
        assert term.terminal_id == i

    # 11th terminal should be rejected
    with pytest.raises(ValueError, match="Maximum 10 terminals reached"):
        await mgr.create_terminal(user_id=user_id, username="user11")


@pytest.mark.asyncio
async def test_pty_session_close_and_cleanup():
    mgr = PTYSessionManager(mock_pty=True)
    user_id = 1001
    await mgr.create_terminal(user_id=user_id, username="root")
    await mgr.create_terminal(user_id=user_id, username="guest")

    # Close terminal 2
    success, msg = await mgr.close_terminal(user_id=user_id, terminal_id=2)
    assert success is True
    assert len(mgr.list_terminals(user_id)) == 1
    assert mgr.get_active_terminal(user_id).terminal_id == 1

    # Cleanup all
    await mgr.close_all_terminals(user_id)
    assert len(mgr.list_terminals(user_id)) == 0
