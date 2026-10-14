"""Tests for identity filtering, update isolation, and replay defense."""

from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock

from src.identity import CHAT_TYPE_PRIVATE, IdentityFilter


class DummyUser:
    def __init__(self, user_id: int):
        self.id = user_id


class DummyChat:
    def __init__(self, chat_id: int, chat_type: str = CHAT_TYPE_PRIVATE):
        self.id = chat_id
        self.type = chat_type


class DummyMessage:
    def __init__(
        self,
        text: str = "/status",
        user_id: int = 1001,
        chat_id: int = 1001,
        chat_type: str = CHAT_TYPE_PRIVATE,
        timestamp: float | None = None,
        is_forwarded: bool = False,
        message_id: int = 42,
    ):
        self.message_id = message_id
        self.text = text
        self.from_user = DummyUser(user_id)
        self.chat = DummyChat(chat_id, chat_type)
        now = timestamp if timestamp is not None else datetime.now(UTC).timestamp()
        self.date = datetime.fromtimestamp(now, tz=UTC)
        self.forward_origin = "origin" if is_forwarded else None
        self.forward_date = None
        self.forward_from = None
        self.forward_from_chat = None


class DummyUpdate:
    def __init__(
        self,
        message: DummyMessage | None = None,
        callback_query: Any = None,
        edited_message: Any = None,
        channel_post: Any = None,
        inline_query: Any = None,
    ):
        self.message = message
        self.callback_query = callback_query
        self.edited_message = edited_message
        self.channel_post = channel_post
        self.edited_channel_post = None
        self.inline_query = inline_query
        self.chosen_inline_result = None


def test_authorized_user_message_allowed():
    identity_filter = IdentityFilter(allowed_user_ids=[1001, 1002])
    msg = DummyMessage(user_id=1001, chat_id=1001, text="/help")
    update = DummyUpdate(message=msg)

    is_valid, reason = identity_filter.validate_update(update)
    assert is_valid is True
    assert reason is None


def test_unknown_sender_rejected_and_audit_rate_limited():
    audit_calls = []

    def fake_audit(event):
        audit_calls.append(event)

    identity_filter = IdentityFilter(
        allowed_user_ids=[1001],
        unknown_audit_cooldown_seconds=60.0,
        audit_logger=fake_audit,
    )

    msg1 = DummyMessage(user_id=9999, chat_id=9999, text="/run ls", timestamp=1000.0)
    update1 = DummyUpdate(message=msg1)

    # First attempt: rejected and logged
    is_valid, reason = identity_filter.validate_update(update1, current_time=1000.0)
    assert is_valid is False
    assert reason == "unknown_sender"
    assert len(audit_calls) == 1
    assert audit_calls[0]["user_id"] == 9999
    assert audit_calls[0]["decision"] == "denied"

    # Rapid second attempt (10s later): rejected, but NOT logged again (cooldown)
    msg2 = DummyMessage(user_id=9999, chat_id=9999, text="/run ls", timestamp=1010.0)
    update2 = DummyUpdate(message=msg2)
    is_valid, reason = identity_filter.validate_update(update2, current_time=1010.0)
    assert is_valid is False
    assert reason == "unknown_sender"
    assert len(audit_calls) == 1

    # Third attempt after 65s: rejected and logged again
    msg3 = DummyMessage(user_id=9999, chat_id=9999, text="/run ls", timestamp=1065.0)
    update3 = DummyUpdate(message=msg3)
    is_valid, reason = identity_filter.validate_update(update3, current_time=1065.0)
    assert is_valid is False
    assert len(audit_calls) == 2


def test_stale_message_rejected():
    identity_filter = IdentityFilter(allowed_user_ids=[1001], max_message_age_seconds=60)
    # Message sent 65 seconds in the past
    msg = DummyMessage(user_id=1001, chat_id=1001, timestamp=935.0)
    update = DummyUpdate(message=msg)

    is_valid, reason = identity_filter.validate_update(update, current_time=1000.0)
    assert is_valid is False
    assert reason == "stale_message"


def test_forwarded_message_rejected():
    identity_filter = IdentityFilter(allowed_user_ids=[1001])
    msg = DummyMessage(user_id=1001, chat_id=1001, is_forwarded=True)
    update = DummyUpdate(message=msg)

    is_valid, reason = identity_filter.validate_update(update)
    assert is_valid is False
    assert reason == "forwarded_message"


def test_group_chat_rejected():
    identity_filter = IdentityFilter(allowed_user_ids=[1001])
    msg = DummyMessage(user_id=1001, chat_id=-100123456, chat_type="group")
    update = DummyUpdate(message=msg)

    is_valid, reason = identity_filter.validate_update(update)
    assert is_valid is False
    assert reason == "non_private_chat"


def test_chat_id_mismatch_rejected():
    identity_filter = IdentityFilter(allowed_user_ids=[1001])
    msg = DummyMessage(user_id=1001, chat_id=1002, chat_type=CHAT_TYPE_PRIVATE)
    update = DummyUpdate(message=msg)

    is_valid, reason = identity_filter.validate_update(update)
    assert is_valid is False
    assert reason == "chat_id_mismatch"


def test_non_text_message_rejected():
    identity_filter = IdentityFilter(allowed_user_ids=[1001])
    msg = DummyMessage(user_id=1001, chat_id=1001, text="")
    msg.text = None
    update = DummyUpdate(message=msg)

    is_valid, reason = identity_filter.validate_update(update)
    assert is_valid is False
    assert reason == "non_text_message"


def test_unsupported_update_types_rejected():
    identity_filter = IdentityFilter(allowed_user_ids=[1001])

    # Edited message
    assert identity_filter.validate_update(DummyUpdate(edited_message=MagicMock())) == (False, "edited_message")

    # Channel post
    assert identity_filter.validate_update(DummyUpdate(channel_post=MagicMock())) == (False, "channel_post")

    # Inline query
    assert identity_filter.validate_update(DummyUpdate(inline_query=MagicMock())) == (False, "inline_query")


def test_callback_query_validation():
    identity_filter = IdentityFilter(allowed_user_ids=[1001])

    # Valid callback from authorized user
    cb_valid = MagicMock()
    cb_valid.from_user.id = 1001
    cb_valid.message.chat.type = CHAT_TYPE_PRIVATE
    cb_valid.message.chat.id = 1001
    is_valid, reason = identity_filter.validate_update(DummyUpdate(callback_query=cb_valid))
    assert is_valid is True
    assert reason is None

    # Unauthorized callback
    cb_unauth = MagicMock()
    cb_unauth.from_user.id = 9999
    is_valid, reason = identity_filter.validate_update(DummyUpdate(callback_query=cb_unauth))
    assert is_valid is False
    assert reason == "unknown_sender"
