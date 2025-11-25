"""
Unit tests for the BaseHoneypotService class.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.base_service import BaseHoneypotService
from core.config import Config


class ConcreteHoneypotService(BaseHoneypotService):
    """Concrete implementation for testing the abstract base class."""

    @property
    def service_name(self) -> str:
        return "test"

    @property
    def port(self) -> int:
        return 9999

    @property
    def protocol(self) -> str:
        return "TCP"

    async def start(self) -> None:
        self._running = True

    async def stop(self) -> None:
        self._running = False

    async def handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        pass


class TestBaseHoneypotService:
    """Tests for BaseHoneypotService abstract class."""

    @pytest.fixture
    def service(self, test_config):
        return ConcreteHoneypotService(test_config)

    def test_service_properties(self, service):
        assert service.service_name == "test"
        assert service.port == 9999
        assert service.protocol == "TCP"

    def test_is_running_initially_false(self, service):
        assert service.is_running is False

    @pytest.mark.asyncio
    async def test_start_sets_running(self, service):
        await service.start()
        assert service.is_running is True

    @pytest.mark.asyncio
    async def test_stop_clears_running(self, service):
        await service.start()
        await service.stop()
        assert service.is_running is False

    def test_connection_count_initially_zero(self, service):
        assert service.connection_count == 0

    def test_generate_session_id(self, service):
        session_id = service._generate_session_id()
        assert isinstance(session_id, str)
        assert len(session_id) == 36  # UUID format

    def test_generate_unique_session_ids(self, service):
        ids = [service._generate_session_id() for _ in range(100)]
        assert len(set(ids)) == 100

    def test_get_client_info(self, service, mock_stream_writer):
        ip, port = service._get_client_info(mock_stream_writer)
        assert ip == "192.168.1.100"
        assert port == 12345

    def test_get_client_info_unknown(self, service):
        writer = MagicMock()
        writer.get_extra_info = MagicMock(return_value=None)
        ip, port = service._get_client_info(writer)
        assert ip == "unknown"
        assert port == 0


class TestDefaultCredentialDetection:
    """Tests for default credential detection."""

    @pytest.fixture
    def service(self, test_config):
        return ConcreteHoneypotService(test_config)

    @pytest.mark.parametrize(
        "username,password,expected",
        [
            ("root", "root", True),
            ("root", "password", True),
            ("admin", "admin", True),
            ("admin", "password", True),
            ("user", "user", True),
            ("pi", "raspberry", True),
            ("ubuntu", "ubuntu", True),
            ("root", "complex_password_123!", False),
            ("customuser", "custompass", False),
            ("admin", "Str0ng!Pass", False),
        ],
    )
    def test_is_default_credential(self, service, username, password, expected):
        result = service._is_default_credential(username, password)
        assert result == expected


class TestSQLInjectionDetection:
    """Tests for SQL injection detection."""

    @pytest.fixture
    def service(self, test_config):
        return ConcreteHoneypotService(test_config)

    @pytest.mark.parametrize(
        "path,body,expected",
        [
            ("/login?id=1' OR '1'='1", None, True),
            ("/search?q=test", None, False),
            ("/api", "user=admin' UNION SELECT * FROM users--", True),
            ("/api", '{"query": "SELECT * FROM products"}', False),
            ("/test?id=1; DROP TABLE users", None, True),
            (None, "1=1", True),
            ("/page?sleep(5)", None, True),
            ("/normal/path", "normal body", False),
        ],
    )
    def test_detect_sql_injection(self, service, path, body, expected):
        result = service._detect_sql_injection(path, body)
        assert result == expected


class TestXSSDetection:
    """Tests for XSS detection."""

    @pytest.fixture
    def service(self, test_config):
        return ConcreteHoneypotService(test_config)

    @pytest.mark.parametrize(
        "path,body,expected",
        [
            ("/search?q=<script>alert('xss')</script>", None, True),
            ("/search?q=hello", None, False),
            ("/api", "<img src=x onerror=alert('xss')>", True),
            ("/api", "normal text content", False),
            ("/page?onclick=evil()", None, True),
            ("/page", "javascript:alert(1)", True),
            ("/page", "document.cookie", True),
            (None, None, False),
        ],
    )
    def test_detect_xss(self, service, path, body, expected):
        result = service._detect_xss(path, body)
        assert result == expected


class TestPathTraversalDetection:
    """Tests for path traversal detection."""

    @pytest.fixture
    def service(self, test_config):
        return ConcreteHoneypotService(test_config)

    @pytest.mark.parametrize(
        "path,expected",
        [
            ("../../../etc/passwd", True),
            ("..\\..\\windows\\system32", True),
            ("/normal/path/file.txt", False),
            ("%2e%2e%2f%2e%2e%2fetc/passwd", True),
            ("....//....//etc/shadow", True),
            ("/var/www/html/index.php", False),
            (None, False),
        ],
    )
    def test_detect_path_traversal(self, service, path, expected):
        result = service._detect_path_traversal(path)
        assert result == expected


class TestRCEDetection:
    """Tests for RCE detection."""

    @pytest.fixture
    def service(self, test_config):
        return ConcreteHoneypotService(test_config)

    @pytest.mark.parametrize(
        "path,body,expected",
        [
            ("/api?cmd=; cat /etc/passwd", None, True),
            ("/api", "| whoami", True),
            ("/search?q=hello", None, False),
            ("/api", "`id`", True),
            ("/api", "$(cat /etc/shadow)", True),
            ("/shell", "/bin/bash -c 'ls'", True),
            ("/normal", "normal request", False),
            ("/cmd", "cmd.exe /c dir", True),
            ("/ps", "powershell -command Get-Process", True),
        ],
    )
    def test_detect_rce(self, service, path, body, expected):
        result = service._detect_rce(path, body)
        assert result == expected


class TestHealthCheck:
    """Tests for health check functionality."""

    @pytest.fixture
    def service(self, test_config):
        return ConcreteHoneypotService(test_config)

    @pytest.mark.asyncio
    async def test_health_check_stopped(self, service):
        health = await service.health_check()
        assert health["service"] == "test"
        assert health["port"] == 9999
        assert health["running"] is False
        assert health["status"] == "stopped"

    @pytest.mark.asyncio
    async def test_health_check_running(self, service):
        await service.start()
        health = await service.health_check()
        assert health["running"] is True
        assert health["status"] == "healthy"
