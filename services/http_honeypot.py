"""
HTTP Honeypot Service

High-interaction HTTP/HTTPS honeypot using aiohttp.
Simulates vulnerable web applications, captures payloads, and logs requests.
"""

from __future__ import annotations

import asyncio
import json
import re
import ssl
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qs, unquote

from aiohttp import web

from core.base_service import BaseHoneypotService
from core.config import Config
from core.logger import ServiceLogger
from services.utils.response_templates import HTTPTemplates
from services.utils.session_manager import get_session_manager


class HTTPHoneypot(BaseHoneypotService):
    """
    HTTP/HTTPS Honeypot Service.
    
    Simulates vulnerable web applications to capture attack payloads,
    credentials, and malicious requests.
    """

    def __init__(self, config: Config):
        super().__init__(config)
        self._app: Optional[web.Application] = None
        self._runner: Optional[web.AppRunner] = None
        self._site: Optional[web.TCPSite] = None
        self._https_site: Optional[web.TCPSite] = None
        self._server_header = HTTPTemplates.get_server_header(config.http.server_header)

    @property
    def service_name(self) -> str:
        return "http"

    @property
    def port(self) -> int:
        return self._config.http.port

    @property
    def protocol(self) -> str:
        return "TCP"

    async def start(self) -> None:
        """Start the HTTP honeypot server."""
        if self._running:
            return

        self._app = web.Application(
            middlewares=[self._logging_middleware, self._security_middleware]
        )
        self._setup_routes()

        self._runner = web.AppRunner(self._app)
        await self._runner.setup()

        # Start HTTP server
        self._site = web.TCPSite(
            self._runner,
            self._config.http.host,
            self._config.http.port,
        )
        await self._site.start()

        # Start HTTPS server if enabled
        if self._config.http.ssl_enabled:
            ssl_context = await self._create_ssl_context()
            if ssl_context:
                self._https_site = web.TCPSite(
                    self._runner,
                    self._config.http.host,
                    self._config.http.https_port,
                    ssl_context=ssl_context,
                )
                await self._https_site.start()
                self._logger.info(
                    "https_enabled",
                    port=self._config.http.https_port,
                )

        self._running = True
        self._logger.info(
            "http_honeypot_started",
            host=self._config.http.host,
            port=self._config.http.port,
        )

    async def stop(self) -> None:
        """Stop the HTTP honeypot server."""
        if not self._running:
            return

        self._running = False

        if self._runner:
            await self._runner.cleanup()
            self._runner = None
            self._site = None
            self._https_site = None

        self._logger.info("http_honeypot_stopped")

    async def handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Not used - aiohttp handles connections internally."""
        pass

    def _setup_routes(self) -> None:
        """Set up HTTP routes for the honeypot."""
        app = self._app

        # Admin panels
        app.router.add_route("*", "/admin", self._handle_admin)
        app.router.add_route("*", "/admin/", self._handle_admin)
        app.router.add_route("*", "/admin/login", self._handle_admin_login)
        app.router.add_route("*", "/administrator", self._handle_admin)
        app.router.add_route("*", "/manager", self._handle_admin)

        # WordPress endpoints
        app.router.add_route("*", "/wp-login.php", self._handle_wp_login)
        app.router.add_route("*", "/wp-admin", self._handle_wp_admin)
        app.router.add_route("*", "/wp-admin/", self._handle_wp_admin)
        app.router.add_route("*", "/wp-content/{path:.*}", self._handle_wp_content)
        app.router.add_route("*", "/xmlrpc.php", self._handle_xmlrpc)

        # Common vulnerable paths
        app.router.add_route("*", "/phpmyadmin", self._handle_phpmyadmin)
        app.router.add_route("*", "/phpmyadmin/", self._handle_phpmyadmin)
        app.router.add_route("*", "/pma", self._handle_phpmyadmin)
        app.router.add_route("*", "/phpinfo.php", self._handle_phpinfo)
        app.router.add_route("*", "/info.php", self._handle_phpinfo)

        # API endpoints
        app.router.add_route("*", "/api/{path:.*}", self._handle_api)
        app.router.add_route("*", "/v1/{path:.*}", self._handle_api)
        app.router.add_route("*", "/v2/{path:.*}", self._handle_api)

        # Config file paths
        app.router.add_route("*", "/.env", self._handle_env_file)
        app.router.add_route("*", "/config.php", self._handle_config_file)
        app.router.add_route("*", "/configuration.php", self._handle_config_file)
        app.router.add_route("*", "/wp-config.php", self._handle_config_file)
        app.router.add_route("*", "/.git/config", self._handle_git_config)
        app.router.add_route("*", "/.git/HEAD", self._handle_git_head)

        # Shell upload paths
        app.router.add_route("*", "/upload", self._handle_upload)
        app.router.add_route("*", "/upload.php", self._handle_upload)
        app.router.add_route("*", "/uploads/{path:.*}", self._handle_uploads_dir)

        # Default catch-all
        app.router.add_route("*", "/{path:.*}", self._handle_default)

    @web.middleware
    async def _logging_middleware(
        self,
        request: web.Request,
        handler: Any,
    ) -> web.Response:
        """Middleware for logging all requests."""
        session_mgr = get_session_manager()
        peername = request.transport.get_extra_info("peername", ("unknown", 0))
        source_ip = peername[0] if peername else "unknown"
        source_port = peername[1] if peername else 0

        # Create session
        session = await session_mgr.create_session(
            source_ip=source_ip,
            source_port=source_port,
            service_type="http",
        )
        await session_mgr.record_request(session.session_id)

        # Store session info in request
        request["honeypot_session_id"] = session.session_id
        request["source_ip"] = source_ip
        request["source_port"] = source_port

        # Log request
        self._logger.info(
            "http_request",
            source_ip=source_ip,
            method=request.method,
            path=request.path,
            query=request.query_string,
            user_agent=request.headers.get("User-Agent", ""),
            session_id=session.session_id,
        )

        # Process request
        try:
            response = await handler(request)
        except web.HTTPException as e:
            response = e

        # Record in database
        await self._record_http_request_from_aiohttp(request, response)

        return response

    @web.middleware
    async def _security_middleware(
        self,
        request: web.Request,
        handler: Any,
    ) -> web.Response:
        """Middleware for adding security headers."""
        response = await handler(request)
        response.headers["Server"] = self._server_header
        response.headers["X-Powered-By"] = "PHP/8.1.2"
        return response

    async def _record_http_request_from_aiohttp(
        self,
        request: web.Request,
        response: web.Response,
    ) -> None:
        """Record HTTP request to database."""
        source_ip = request.get("source_ip", "unknown")
        source_port = request.get("source_port", 0)

        # Get request body
        try:
            body = await request.text()
        except Exception:
            body = None

        # Create attack record
        attack = await self._record_attack(
            source_ip=source_ip,
            source_port=source_port,
            attack_type=self._classify_request(request, body),
            severity=self._calculate_severity(request, body),
        )

        # Record HTTP request details
        await self._record_http_request(
            attack_id=attack.id,
            method=request.method,
            path=request.path,
            query_string=request.query_string or None,
            headers=dict(request.headers),
            body=body,
            user_agent=request.headers.get("User-Agent"),
            response_status=response.status,
        )

    def _classify_request(self, request: web.Request, body: Optional[str]) -> str:
        """Classify the type of attack based on request."""
        path = request.path.lower()
        method = request.method

        # Check for common attack patterns
        full_text = f"{path} {request.query_string or ''} {body or ''}".lower()

        if self._detect_sql_injection(path, body):
            return "sql_injection"
        if self._detect_xss(path, body):
            return "xss"
        if self._detect_path_traversal(path):
            return "path_traversal"
        if self._detect_rce(path, body):
            return "rce"

        # Check path patterns
        if any(p in path for p in ["/admin", "/wp-admin", "/phpmyadmin", "/manager"]):
            return "admin_probe"
        if any(p in path for p in [".env", "config", ".git"]):
            return "config_exposure"
        if "login" in path or (method == "POST" and ("password" in (body or "").lower())):
            return "credential_attack"
        if any(p in path for p in ["/shell", "/cmd", "/exec", "/c99", "/r57"]):
            return "webshell_probe"
        if method == "POST" and any(p in path for p in ["/upload", "/file"]):
            return "file_upload"
        if "xmlrpc" in path:
            return "xmlrpc_attack"

        return "reconnaissance"

    def _calculate_severity(self, request: web.Request, body: Optional[str]) -> int:
        """Calculate severity based on attack type."""
        attack_type = self._classify_request(request, body)

        severity_map = {
            "sql_injection": 8,
            "rce": 9,
            "xss": 6,
            "path_traversal": 7,
            "file_upload": 7,
            "webshell_probe": 8,
            "credential_attack": 5,
            "admin_probe": 3,
            "config_exposure": 6,
            "xmlrpc_attack": 5,
            "reconnaissance": 2,
        }

        return severity_map.get(attack_type, 3)

    async def _handle_admin(self, request: web.Request) -> web.Response:
        """Handle admin panel requests."""
        if request.method == "GET":
            return web.Response(
                text=HTTPTemplates.get_login_page(),
                content_type="text/html",
            )
        return web.HTTPFound("/admin/login")

    async def _handle_admin_login(self, request: web.Request) -> web.Response:
        """Handle admin login POST."""
        if request.method == "POST":
            try:
                data = await request.post()
                username = data.get("username", "")
                password = data.get("password", "")

                self._logger.warning(
                    "http_login_attempt",
                    source_ip=request.get("source_ip"),
                    username=username,
                    path=request.path,
                )

                # Always fail login
                return web.Response(
                    text=HTTPTemplates.get_login_page("Invalid username or password"),
                    content_type="text/html",
                )
            except Exception:
                pass

        return web.Response(
            text=HTTPTemplates.get_login_page(),
            content_type="text/html",
        )

    async def _handle_wp_login(self, request: web.Request) -> web.Response:
        """Handle WordPress login."""
        if request.method == "POST":
            try:
                data = await request.post()
                username = data.get("log", "")
                password = data.get("pwd", "")

                self._logger.warning(
                    "http_wp_login_attempt",
                    source_ip=request.get("source_ip"),
                    username=username,
                )

                return web.Response(
                    text=HTTPTemplates.get_login_page(
                        "Error: Invalid username or password.",
                        wordpress=True,
                    ),
                    content_type="text/html",
                )
            except Exception:
                pass

        return web.Response(
            text=HTTPTemplates.get_login_page(wordpress=True),
            content_type="text/html",
        )

    async def _handle_wp_admin(self, request: web.Request) -> web.Response:
        """Redirect wp-admin to login."""
        return web.HTTPFound("/wp-login.php")

    async def _handle_wp_content(self, request: web.Request) -> web.Response:
        """Handle wp-content requests."""
        return web.Response(
            text=HTTPTemplates.get_error_page(404, request.path),
            status=404,
            content_type="text/html",
        )

    async def _handle_xmlrpc(self, request: web.Request) -> web.Response:
        """Handle XML-RPC requests (common WordPress attack vector)."""
        self._logger.warning(
            "http_xmlrpc_request",
            source_ip=request.get("source_ip"),
            method=request.method,
        )

        if request.method == "POST":
            try:
                body = await request.text()
                self._logger.info(
                    "http_xmlrpc_payload",
                    source_ip=request.get("source_ip"),
                    payload=body[:500],
                )
            except Exception:
                pass

        # Return a fake XML-RPC response
        response = """<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <fault>
    <value>
      <struct>
        <member>
          <name>faultCode</name>
          <value><int>403</int></value>
        </member>
        <member>
          <name>faultString</name>
          <value><string>Forbidden</string></value>
        </member>
      </struct>
    </value>
  </fault>
</methodResponse>"""
        return web.Response(text=response, content_type="text/xml")

    async def _handle_phpmyadmin(self, request: web.Request) -> web.Response:
        """Handle phpMyAdmin requests."""
        html = """<!DOCTYPE html>
<html>
<head><title>phpMyAdmin</title></head>
<body>
<h1>phpMyAdmin</h1>
<form method="post" action="/phpmyadmin/">
    <input type="text" name="pma_username" placeholder="Username">
    <input type="password" name="pma_password" placeholder="Password">
    <button type="submit">Login</button>
</form>
</body>
</html>"""

        if request.method == "POST":
            try:
                data = await request.post()
                username = data.get("pma_username", "")
                password = data.get("pma_password", "")

                self._logger.warning(
                    "http_phpmyadmin_login",
                    source_ip=request.get("source_ip"),
                    username=username,
                )
            except Exception:
                pass

        return web.Response(text=html, content_type="text/html")

    async def _handle_phpinfo(self, request: web.Request) -> web.Response:
        """Handle phpinfo requests."""
        source_ip = request.get("source_ip", "unknown")
        html = HTTPTemplates.PHPINFO_FAKE.format(remote_addr=source_ip)
        return web.Response(text=html, content_type="text/html")

    async def _handle_api(self, request: web.Request) -> web.Response:
        """Handle API endpoint requests."""
        path = request.match_info.get("path", "")

        self._logger.info(
            "http_api_request",
            source_ip=request.get("source_ip"),
            path=f"/api/{path}",
            method=request.method,
        )

        # Return fake API response
        response_data = {
            "status": "error",
            "message": "Unauthorized",
            "code": 401,
        }
        return web.json_response(response_data, status=401)

    async def _handle_env_file(self, request: web.Request) -> web.Response:
        """Handle .env file requests with fake credentials."""
        self._logger.warning(
            "http_env_probe",
            source_ip=request.get("source_ip"),
        )

        # Return fake .env content (honeytokens)
        fake_env = """APP_NAME=Laravel
APP_ENV=production
APP_KEY=base64:fakeapplicationkeynotreal123456=
APP_DEBUG=false
APP_URL=http://localhost

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=laravel
DB_USERNAME=laravel_user
DB_PASSWORD=fake_db_password_123

MAIL_MAILER=smtp
MAIL_HOST=smtp.mailtrap.io
MAIL_USERNAME=fake_mail_user
MAIL_PASSWORD=fake_mail_pass

AWS_ACCESS_KEY_ID=AKIAFAKEACCESSKEY123
AWS_SECRET_ACCESS_KEY=fakesecretaccesskey/notreal/123456789
"""
        return web.Response(text=fake_env, content_type="text/plain")

    async def _handle_config_file(self, request: web.Request) -> web.Response:
        """Handle config file requests."""
        self._logger.warning(
            "http_config_probe",
            source_ip=request.get("source_ip"),
            path=request.path,
        )
        return web.Response(
            text=HTTPTemplates.get_error_page(403, request.path),
            status=403,
            content_type="text/html",
        )

    async def _handle_git_config(self, request: web.Request) -> web.Response:
        """Handle .git/config requests."""
        self._logger.warning(
            "http_git_probe",
            source_ip=request.get("source_ip"),
        )

        config = """[core]
    repositoryformatversion = 0
    filemode = true
    bare = false
[remote "origin"]
    url = https://github.com/example/webapp.git
    fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
    remote = origin
    merge = refs/heads/main
"""
        return web.Response(text=config, content_type="text/plain")

    async def _handle_git_head(self, request: web.Request) -> web.Response:
        """Handle .git/HEAD requests."""
        return web.Response(text="ref: refs/heads/main\n", content_type="text/plain")

    async def _handle_upload(self, request: web.Request) -> web.Response:
        """Handle file upload attempts."""
        if request.method == "POST":
            try:
                reader = await request.multipart()
                async for part in reader:
                    if part.filename:
                        content = await part.read()

                        self._logger.warning(
                            "http_file_upload",
                            source_ip=request.get("source_ip"),
                            filename=part.filename,
                            size=len(content),
                            content_type=part.headers.get("Content-Type"),
                        )

                        # Record file upload
                        attack = await self._record_attack(
                            source_ip=request.get("source_ip", "unknown"),
                            source_port=request.get("source_port", 0),
                            attack_type="file_upload",
                            severity=7,
                        )

                        await self._record_file(
                            attack_id=attack.id,
                            filename=part.filename,
                            content=content,
                            operation="upload",
                        )

            except Exception as e:
                self._logger.error("upload_error", error=str(e))

        # Return fake success
        return web.json_response({"status": "success", "message": "File uploaded"})

    async def _handle_uploads_dir(self, request: web.Request) -> web.Response:
        """Handle requests to uploads directory."""
        return web.Response(
            text=HTTPTemplates.get_error_page(403, request.path),
            status=403,
            content_type="text/html",
        )

    async def _handle_default(self, request: web.Request) -> web.Response:
        """Handle all other requests."""
        path = request.path

        # Check for shell patterns
        shell_patterns = [".php", ".asp", ".jsp", ".cgi", "shell", "cmd", "exec"]
        if any(p in path.lower() for p in shell_patterns):
            self._logger.warning(
                "http_shell_probe",
                source_ip=request.get("source_ip"),
                path=path,
            )

        # Return 404 for unknown paths
        return web.Response(
            text=HTTPTemplates.get_error_page(404, path),
            status=404,
            content_type="text/html",
        )

    async def _create_ssl_context(self) -> Optional[ssl.SSLContext]:
        """Create SSL context for HTTPS."""
        cert_path = self._config.http.ssl_cert_path
        key_path = self._config.http.ssl_key_path

        if not cert_path or not key_path:
            # Generate self-signed certificate
            cert_dir = Path("data/certs")
            cert_dir.mkdir(parents=True, exist_ok=True)
            cert_path = str(cert_dir / "server.crt")
            key_path = str(cert_dir / "server.key")

            if not Path(cert_path).exists():
                self._logger.info("generating_ssl_certificate")
                await self._generate_self_signed_cert(cert_path, key_path)

        try:
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(cert_path, key_path)
            return ssl_context
        except Exception as e:
            self._logger.error("ssl_context_error", error=str(e))
            return None

    async def _generate_self_signed_cert(
        self,
        cert_path: str,
        key_path: str,
    ) -> None:
        """Generate a self-signed SSL certificate."""
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.x509.oid import NameOID

            # Generate key
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend(),
            )

            # Generate certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Organization"),
                x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
            ])

            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.utcnow())
                .not_valid_after(datetime.utcnow() + timedelta(days=365))
                .sign(key, hashes.SHA256(), default_backend())
            )

            # Write key
            with open(key_path, "wb") as f:
                f.write(key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                ))

            # Write cert
            with open(cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))

        except ImportError:
            self._logger.warning("cryptography_not_installed")
        except Exception as e:
            self._logger.error("cert_generation_error", error=str(e))


# Import timedelta for certificate generation
from datetime import timedelta
