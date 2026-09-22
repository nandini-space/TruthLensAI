"""Offline unit tests for the Module 3C Telegram prototype interaction logic."""

from __future__ import annotations

import asyncio
import ast
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from module_3c.telegram_bot.actions import CallbackAction
from module_3c.telegram_bot.config import BotConfigurationError, TelegramBotSettings
from module_3c.telegram_bot.interaction import (
    help_reply,
    main_menu,
    reply_for_action,
    unexpected_input,
)


class TelegramBotInteractionTests(unittest.TestCase):
    def test_start_main_menu_has_expected_actions(self) -> None:
        reply = main_menu(welcome=True)
        self.assertIn("Welcome to TruthLensAI", reply.text)
        self.assertEqual(
            [button.action for row in reply.keyboard for button in row],
            [CallbackAction.NEW_SCAN, CallbackAction.SCAN_HISTORY, CallbackAction.HELP],
        )

    def test_help_and_cancel_return_safe_prototype_responses(self) -> None:
        self.assertIn("does not scan", help_reply().text)
        self.assertEqual(reply_for_action(CallbackAction.CANCEL.value), main_menu())

    def test_new_scan_opens_all_input_choices(self) -> None:
        reply = reply_for_action(CallbackAction.NEW_SCAN.value)
        actions = [button.action for row in reply.keyboard for button in row]
        self.assertEqual(
            actions,
            [
                CallbackAction.SCAN_TEXT,
                CallbackAction.SCAN_URL,
                CallbackAction.SCAN_IMAGE,
                CallbackAction.SCAN_AUDIO,
                CallbackAction.SCAN_VIDEO,
                CallbackAction.CANCEL,
            ],
        )

    def test_every_input_selection_is_confirmation_only(self) -> None:
        for action in (
            CallbackAction.SCAN_TEXT,
            CallbackAction.SCAN_URL,
            CallbackAction.SCAN_IMAGE,
            CallbackAction.SCAN_AUDIO,
            CallbackAction.SCAN_VIDEO,
        ):
            with self.subTest(action=action):
                reply = reply_for_action(action.value)
                self.assertIn("scan selected", reply.text)
                self.assertIn("connected in a later task", reply.text)
                self.assertEqual(reply.keyboard[0][0].action, CallbackAction.CANCEL)

    def test_unknown_callback_and_unexpected_input_are_safe(self) -> None:
        self.assertIn("unavailable", reply_for_action("NOT_A_REAL_ACTION").text)
        self.assertIn("Please use /start", unexpected_input().text)

    def test_scan_history_is_explicitly_unavailable(self) -> None:
        self.assertIn("not available yet", reply_for_action(CallbackAction.SCAN_HISTORY.value).text)

    def test_missing_token_is_a_clear_configuration_error(self) -> None:
        with patch.dict(os.environ, {"TELEGRAM_BOT_TOKEN": ""}, clear=False):
            with self.assertRaisesRegex(BotConfigurationError, "TELEGRAM_BOT_TOKEN is required"):
                TelegramBotSettings.from_environment()

    def test_bot_package_has_no_backend_or_n8n_imports(self) -> None:
        package = Path("module_3c/telegram_bot")
        imported_modules: set[str] = set()
        for path in package.glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported_modules.update(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported_modules.add(node.module)
        self.assertFalse(
            any(name == "backend" or name.startswith("backend.") for name in imported_modules)
        )
        self.assertFalse(any(name == "n8n" or name.startswith("n8n.") for name in imported_modules))

    def test_real_handlers_render_fake_updates_without_network(self) -> None:
        from module_3c.telegram_bot.handlers import cancel, help_command, start

        class FakeMessage:
            def __init__(self) -> None:
                self.replies = []

            async def reply_text(self, text, reply_markup) -> None:
                self.replies.append((text, reply_markup))

        class FakeUpdate:
            def __init__(self) -> None:
                self.effective_message = FakeMessage()

        for handler, expected_text in (
            (start, "Welcome to TruthLensAI"),
            (help_command, "does not scan"),
            (cancel, "Choose an option"),
        ):
            with self.subTest(handler=handler.__name__):
                update = FakeUpdate()
                asyncio.run(handler(update, None))
                self.assertIn(expected_text, update.effective_message.replies[0][0])

    def test_bot_application_is_constructed_without_starting_polling(self) -> None:
        from module_3c.telegram_bot.bot import create_application

        application = create_application(TelegramBotSettings(token="test-token"))
        self.assertGreaterEqual(len(application.handlers[0]), 5)

    def test_unknown_callback_handler_answers_and_returns_to_a_safe_menu(self) -> None:
        from module_3c.telegram_bot.handlers import callback_action

        class FakeQuery:
            data = "NOT_A_REAL_ACTION"

            def __init__(self) -> None:
                self.answered = False
                self.edited = None

            async def answer(self) -> None:
                self.answered = True

            async def edit_message_text(self, text, reply_markup) -> None:
                self.edited = (text, reply_markup)

        class FakeUpdate:
            def __init__(self) -> None:
                self.callback_query = FakeQuery()

        update = FakeUpdate()
        asyncio.run(callback_action(update, None))
        self.assertTrue(update.callback_query.answered)
        self.assertIn("unavailable", update.callback_query.edited[0])


if __name__ == "__main__":
    unittest.main()
