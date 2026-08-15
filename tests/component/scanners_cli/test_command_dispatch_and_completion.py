"""Noninteractive command dispatch and path completion contracts."""

import importlib
import sys

import pytest
from prompt_toolkit.completion import CompleteEvent
from prompt_toolkit.document import Document

from aiosmb.examples.smbpathcompleter import SMBPathCompleter


pytestmark = pytest.mark.component


def load_smbclient():
    if sys.version_info < (3, 9):
        pytest.skip("blocked by KF-0107")
    return importlib.import_module("aiosmb.examples.smbclient")


class FakeClient:
    instances = []
    command_results = {}

    def __init__(self, url, silent=False, nosig=False):
        self.url = url
        self.silent = silent
        self.nosig = nosig
        self.commands = []
        self.login_calls = 0
        self.run_calls = 0
        self.logout_calls = 0
        self.instances.append(self)

    async def do_login(self):
        self.login_calls += 1
        return True, None

    async def _run_single_command(self, command, arguments):
        self.commands.append((command, arguments))
        return self.command_results.get(command, (True, None))

    async def run(self):
        self.run_calls += 1

    async def do_logout(self):
        self.logout_calls += 1


@pytest.mark.asyncio
async def test_no_interactive_without_commands_exits_before_network(
    monkeypatch, capsys
) -> None:
    module = load_smbclient()
    FakeClient.instances = []
    monkeypatch.setattr(module, "SMBClient", FakeClient)

    with pytest.raises(SystemExit) as raised:
        await module.amain(
            "smb://files.example",
            commands=[],
            no_interactive=True,
        )

    assert raised.value.code == 1
    assert "Not starting interactive!" in capsys.readouterr().out
    client = FakeClient.instances[-1]
    assert client.login_calls == 0
    assert client.run_calls == 0


@pytest.mark.asyncio
async def test_batch_dispatch_splits_arguments_handles_login_and_logs_out(
    monkeypatch,
) -> None:
    module = load_smbclient()
    FakeClient.instances = []
    FakeClient.command_results = {}
    monkeypatch.setattr(module, "SMBClient", FakeClient)

    with pytest.raises(SystemExit) as raised:
        await module.amain(
            "smb://files.example",
            commands=["login", 'servicecreate svc "cmd /c whoami"'],
            silent=True,
            nosig=True,
        )

    assert raised.value.code == 0
    client = FakeClient.instances[-1]
    assert client.url == "smb://files.example"
    assert client.silent is True
    assert client.nosig is True
    assert client.login_calls == 1
    assert client.commands == [
        ("servicecreate", ["svc", "cmd /c whoami"])
    ]
    assert client.logout_calls == 1


@pytest.mark.asyncio
async def test_batch_dispatch_stops_on_error_and_still_logs_out(
    monkeypatch, capsys
) -> None:
    module = load_smbclient()
    FakeClient.instances = []
    FakeClient.command_results = {
        "bad": (None, RuntimeError("failed")),
        "later": (True, None),
    }
    monkeypatch.setattr(module, "SMBClient", FakeClient)

    with pytest.raises(SystemExit) as raised:
        await module.amain(
            "smb://files.example",
            commands=["bad", "later"],
            continue_on_error=False,
        )

    assert raised.value.code == 1
    client = FakeClient.instances[-1]
    assert client.commands == [("bad", [])]
    assert client.logout_calls == 1
    assert "Batch execution stopped early" in capsys.readouterr().out


@pytest.mark.asyncio
async def test_batch_dispatch_continues_after_error_when_requested(
    monkeypatch,
) -> None:
    module = load_smbclient()
    FakeClient.instances = []
    FakeClient.command_results = {
        "bad": (None, RuntimeError("failed")),
        "later": (True, None),
    }
    monkeypatch.setattr(module, "SMBClient", FakeClient)

    with pytest.raises(SystemExit) as raised:
        await module.amain(
            "smb://files.example",
            commands=["bad", "later"],
            continue_on_error=True,
        )

    assert raised.value.code == 0
    client = FakeClient.instances[-1]
    assert client.commands == [("bad", []), ("later", [])]
    assert client.logout_calls == 1


def test_path_completer_returns_prefix_matches_from_all_current_locations() -> None:
    completer = SMBPathCompleter(
        get_current_dirs=lambda: ["alpha", "alpine", "beta", "alpha"]
    )

    completions = list(
        completer.get_completions(
            Document("al", cursor_position=2),
            CompleteEvent(completion_requested=True),
        )
    )

    assert [(item.text, item.display_text) for item in completions] == [
        ("pha", "alpha"),
        ("pine", "alpine"),
        ("pha", "alpha"),
    ]
    assert all(item.start_position == 0 for item in completions)


def test_path_completer_honors_minimum_input_length() -> None:
    calls = []
    completer = SMBPathCompleter(
        get_current_dirs=lambda: calls.append(True) or ["alpha"],
        min_input_len=2,
    )

    completions = list(
        completer.get_completions(
            Document("a", cursor_position=1),
            CompleteEvent(completion_requested=True),
        )
    )

    assert completions == []
    assert calls == []


def test_path_completer_uses_text_only_before_cursor() -> None:
    completer = SMBPathCompleter(get_current_dirs=lambda: ["alpha", "beta"])

    completions = list(
        completer.get_completions(
            Document("alpha trailing", cursor_position=2),
            CompleteEvent(completion_requested=True),
        )
    )

    assert [(item.text, item.display_text) for item in completions] == [
        ("pha", "alpha")
    ]
