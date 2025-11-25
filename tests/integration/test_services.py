"""
Integration tests for honeypot services.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.utils.fake_filesystem import FakeFilesystem, FileType
from services.utils.response_templates import (
    FTPTemplates,
    HTTPTemplates,
    ShellTemplates,
    SSHTemplates,
)
from services.utils.session_manager import (
    Session,
    SessionManager,
    SessionState,
    get_session_manager,
)


class TestFakeFilesystem:
    """Tests for the fake filesystem."""

    def test_initial_state(self):
        fs = FakeFilesystem()
        assert fs.getcwd() == "/"
        assert fs.exists("/")
        assert fs.is_dir("/")

    def test_standard_directories_exist(self):
        fs = FakeFilesystem()
        standard_dirs = ["/bin", "/etc", "/home", "/root", "/var", "/tmp"]
        for d in standard_dirs:
            assert fs.exists(d), f"Directory {d} should exist"
            assert fs.is_dir(d), f"{d} should be a directory"

    def test_etc_passwd_exists(self):
        fs = FakeFilesystem()
        assert fs.exists("/etc/passwd")
        assert fs.is_file("/etc/passwd")

        content = fs.read_file("/etc/passwd")
        assert b"root" in content
        assert b"/bin/bash" in content

    def test_etc_shadow_exists(self):
        fs = FakeFilesystem()
        assert fs.exists("/etc/shadow")
        content = fs.read_file("/etc/shadow")
        assert b"root:" in content

    def test_chdir(self):
        fs = FakeFilesystem()
        assert fs.chdir("/etc")
        assert fs.getcwd() == "/etc"

        assert fs.chdir("/nonexistent") is False
        assert fs.getcwd() == "/etc"

    def test_listdir(self):
        fs = FakeFilesystem()
        entries = fs.listdir("/etc")
        assert "passwd" in entries
        assert "shadow" in entries
        assert "hostname" in entries

    def test_ls_output(self):
        fs = FakeFilesystem()
        output = fs.ls("/etc")
        assert "passwd" in output

        long_output = fs.ls("/etc", long_format=True)
        assert "root" in long_output

    def test_relative_path_resolution(self):
        fs = FakeFilesystem()
        fs.chdir("/home")
        assert fs.exists("admin")

    def test_write_file(self):
        fs = FakeFilesystem()
        fs.write_file("/tmp/test.txt", b"test content")
        assert fs.exists("/tmp/test.txt")
        assert fs.read_file("/tmp/test.txt") == b"test content"


class TestSSHTemplates:
    """Tests for SSH response templates."""

    def test_banner_format(self):
        banner = SSHTemplates.get_banner()
        assert banner.startswith("SSH-2.0-")

    def test_custom_banner(self):
        custom = "SSH-2.0-CustomServer_1.0"
        banner = SSHTemplates.get_banner(custom)
        assert banner == custom

    def test_motd_contains_system_info(self):
        motd = SSHTemplates.get_motd("10.0.0.1")
        assert "Ubuntu" in motd
        assert "10.0.0.1" in motd
        assert "Last login" in motd

    def test_auth_failed_message(self):
        msg = SSHTemplates.get_auth_failed()
        assert "denied" in msg.lower() or "permission" in msg.lower()


class TestShellTemplates:
    """Tests for shell command templates."""

    def test_uname(self):
        output = ShellTemplates.get_uname()
        assert "Linux" in output

        output = ShellTemplates.get_uname("-a")
        assert "Linux" in output
        assert "GNU/Linux" in output

    def test_id_root(self):
        output = ShellTemplates.get_id("root", 0, 0)
        assert "uid=0(root)" in output
        assert "gid=0(root)" in output

    def test_id_user(self):
        output = ShellTemplates.get_id("admin", 1000, 1000)
        assert "uid=1000(admin)" in output

    def test_ps_output(self):
        output = ShellTemplates.get_ps("admin")
        assert "PID" in output
        assert "admin" in output
        assert "bash" in output

    def test_netstat_output(self):
        output = ShellTemplates.get_netstat()
        assert "LISTEN" in output
        assert ":22" in output

    def test_unknown_command(self):
        output = ShellTemplates.get_unknown_command("foobar")
        assert "foobar" in output
        assert "command not found" in output


class TestHTTPTemplates:
    """Tests for HTTP response templates."""

    def test_server_header(self):
        header = HTTPTemplates.get_server_header()
        assert any(s in header for s in ["Apache", "nginx", "IIS"])

    def test_custom_server_header(self):
        custom = "CustomServer/1.0"
        header = HTTPTemplates.get_server_header(custom)
        assert header == custom

    def test_error_404(self):
        page = HTTPTemplates.get_error_page(404, "/missing")
        assert "404" in page
        assert "Not Found" in page
        assert "/missing" in page

    def test_error_403(self):
        page = HTTPTemplates.get_error_page(403, "/forbidden")
        assert "403" in page
        assert "Forbidden" in page

    def test_login_page(self):
        page = HTTPTemplates.get_login_page()
        assert "login" in page.lower()
        assert "password" in page.lower()

    def test_login_page_with_error(self):
        page = HTTPTemplates.get_login_page("Invalid credentials")
        assert "Invalid credentials" in page

    def test_wordpress_login(self):
        page = HTTPTemplates.get_login_page(wordpress=True)
        assert "WordPress" in page
        assert "wp-submit" in page


class TestFTPTemplates:
    """Tests for FTP response templates."""

    def test_banner(self):
        banner = FTPTemplates.get_banner()
        assert "220" in banner

    def test_responses(self):
        assert "331" in FTPTemplates.get_response("user_ok")
        assert "230" in FTPTemplates.get_response("login_ok")
        assert "530" in FTPTemplates.get_response("login_fail")
        assert "257" in FTPTemplates.get_response("pwd", path="/home")

    def test_list_entry_file(self):
        entry = FTPTemplates.format_list_entry("test.txt", is_dir=False, size=1024)
        assert "test.txt" in entry
        assert "1024" in entry
        assert entry.startswith("-")

    def test_list_entry_directory(self):
        entry = FTPTemplates.format_list_entry("subdir", is_dir=True)
        assert "subdir" in entry
        assert entry.startswith("d")


class TestSessionManager:
    """Tests for the session manager."""

    @pytest.fixture
    def session_manager(self):
        return SessionManager(session_timeout=3600, cleanup_interval=300)

    @pytest.mark.asyncio
    async def test_create_session(self, session_manager):
        session = await session_manager.create_session(
            source_ip="192.168.1.100",
            source_port=54321,
            service_type="ssh",
        )

        assert session.session_id is not None
        assert session.source_ip == "192.168.1.100"
        assert session.source_port == 54321
        assert session.service_type == "ssh"
        assert session.state == SessionState.CONNECTING

    @pytest.mark.asyncio
    async def test_get_session(self, session_manager):
        created = await session_manager.create_session(
            source_ip="192.168.1.100",
            source_port=54321,
            service_type="ssh",
        )

        retrieved = await session_manager.get_session(created.session_id)
        assert retrieved is not None
        assert retrieved.session_id == created.session_id

    @pytest.mark.asyncio
    async def test_update_session_state(self, session_manager):
        session = await session_manager.create_session(
            source_ip="192.168.1.100",
            source_port=54321,
            service_type="ssh",
        )

        result = await session_manager.update_session_state(
            session.session_id,
            SessionState.AUTHENTICATED,
        )
        assert result is True

        updated = await session_manager.get_session(session.session_id)
        assert updated.state == SessionState.AUTHENTICATED

    @pytest.mark.asyncio
    async def test_set_authenticated(self, session_manager):
        session = await session_manager.create_session(
            source_ip="192.168.1.100",
            source_port=54321,
            service_type="ssh",
        )

        await session_manager.set_authenticated(session.session_id, "admin")

        updated = await session_manager.get_session(session.session_id)
        assert updated.username == "admin"
        assert updated.state == SessionState.AUTHENTICATED
        assert updated.stats.successful_auth is True

    @pytest.mark.asyncio
    async def test_record_auth_attempt(self, session_manager):
        session = await session_manager.create_session(
            source_ip="192.168.1.100",
            source_port=54321,
            service_type="ssh",
        )

        for _ in range(3):
            await session_manager.record_auth_attempt(session.session_id)

        updated = await session_manager.get_session(session.session_id)
        assert updated.stats.auth_attempts == 3

    @pytest.mark.asyncio
    async def test_record_command(self, session_manager):
        session = await session_manager.create_session(
            source_ip="192.168.1.100",
            source_port=54321,
            service_type="ssh",
        )

        for _ in range(5):
            await session_manager.record_command(session.session_id)

        updated = await session_manager.get_session(session.session_id)
        assert updated.stats.commands_executed == 5

    @pytest.mark.asyncio
    async def test_record_file_upload(self, session_manager):
        session = await session_manager.create_session(
            source_ip="192.168.1.100",
            source_port=54321,
            service_type="ftp",
        )

        await session_manager.record_file_upload(session.session_id, 1024)
        await session_manager.record_file_upload(session.session_id, 2048)

        updated = await session_manager.get_session(session.session_id)
        assert updated.stats.files_uploaded == 2
        assert updated.stats.bytes_received == 3072

    @pytest.mark.asyncio
    async def test_close_session(self, session_manager):
        session = await session_manager.create_session(
            source_ip="192.168.1.100",
            source_port=54321,
            service_type="ssh",
        )

        closed = await session_manager.close_session(session.session_id)
        assert closed is not None
        assert closed.state == SessionState.CLOSED
        assert closed.ended_at is not None

    @pytest.mark.asyncio
    async def test_get_active_sessions(self, session_manager):
        # Create multiple sessions
        await session_manager.create_session("10.0.0.1", 1001, "ssh")
        await session_manager.create_session("10.0.0.2", 1002, "http")
        s3 = await session_manager.create_session("10.0.0.3", 1003, "ssh")

        # Close one
        await session_manager.close_session(s3.session_id)

        active = await session_manager.get_active_sessions()
        assert len(active) == 2

        ssh_active = await session_manager.get_active_sessions("ssh")
        assert len(ssh_active) == 1

    @pytest.mark.asyncio
    async def test_get_sessions_by_ip(self, session_manager):
        await session_manager.create_session("192.168.1.100", 1001, "ssh")
        await session_manager.create_session("192.168.1.100", 1002, "http")
        await session_manager.create_session("10.0.0.1", 1003, "ssh")

        sessions = await session_manager.get_sessions_by_ip("192.168.1.100")
        assert len(sessions) == 2

    @pytest.mark.asyncio
    async def test_get_stats(self, session_manager):
        await session_manager.create_session("10.0.0.1", 1001, "ssh")
        await session_manager.create_session("10.0.0.2", 1002, "http")
        s3 = await session_manager.create_session("10.0.0.3", 1003, "ftp")
        await session_manager.close_session(s3.session_id)

        stats = await session_manager.get_stats()
        assert stats["total_sessions"] == 3
        assert stats["active_sessions"] == 2
        assert stats["closed_sessions"] == 1
        assert stats["by_service"]["ssh"] == 1
        assert stats["by_service"]["http"] == 1
        assert stats["by_service"]["ftp"] == 1

    @pytest.mark.asyncio
    async def test_session_to_dict(self, session_manager):
        session = await session_manager.create_session(
            source_ip="192.168.1.100",
            source_port=54321,
            service_type="ssh",
        )

        data = session.to_dict()
        assert data["session_id"] == session.session_id
        assert data["source_ip"] == "192.168.1.100"
        assert data["service_type"] == "ssh"
        assert "started_at" in data
        assert "duration_seconds" in data
