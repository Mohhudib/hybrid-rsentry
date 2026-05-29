import pytest
from unittest.mock import MagicMock

@pytest.fixture
def fake_process():
    proc = MagicMock()
    proc.pid = 1234
    proc.name.return_value = "bash"
    proc.exe.return_value = "/usr/bin/bash"
    proc.parent.return_value = None
    return proc

@pytest.fixture
def tmp_canary_dir(tmp_path):
    (tmp_path / "AAA_secret.docx").write_bytes(b"fake content")
    (tmp_path / "AAA_passwords.txt").write_bytes(b"more fake content")
    (tmp_path / "regular_file.txt").write_bytes(b"normal data")
    return tmp_path
