"""
FTP Honeypot Service

High-interaction FTP honeypot using asyncio.
Captures credentials, file uploads/downloads, and logs all FTP commands.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

from core.base_service import BaseHoneypotService
from core.config import Config
from core.logger import ServiceLogger
from services.utils.fake_filesystem import FakeFilesystem, FileNode
from services.utils.response_templates import FTPTemplates
from services.utils.session_manager import get_session_manager, SessionState


class FTPClientHandler:
    """Handles a single FTP client connection."""

    def __init__(
        self,
        honeypot: "FTPHoneypot",
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        self._honeypot = honeypot
        self._reader = reader
        self._writer = writer
        self._config = honeypot._config

        # Connection info
        peername = writer.get_extra_info("peername", ("unknown", 0))
        self._source_ip = peername[0]
        self._source_port = peername[1]

        # Session state
        self._session_id: Optional[str] = None
        self._authenticated = False
        self._username: Optional[str] = None
        self._attack_id: Optional[int] = None

        # FTP state
        self._fs = FakeFilesystem()
        self._transfer_type = "A"  # ASCII or Binary
        self._passive_mode = False
        self._data_port: Optional[int] = None
        self._data_host: Optional[str] = None
        self._data_server: Optional[asyncio.Server] = None
        self._data_connection: Optional[tuple] = None

        # Upload storage
        self._upload_dir = Path("data/uploads/ftp")
        self._upload_dir.mkdir(parents=True, exist_ok=True)

    async def handle(self) -> None:
        """Main handler for the FTP connection."""
        session_mgr = get_session_manager()

        # Create session
        session = await session_mgr.create_session(
            source_ip=self._source_ip,
            source_port=self._source_port,
            service_type="ftp",
        )
        self._session_id = session.session_id

        self._honeypot._logger.connection(
            source_ip=self._source_ip,
            source_port=self._source_port,
            event="ftp_connection",
            session_id=self._session_id,
        )

        try:
            # Send banner
            await self._send(FTPTemplates.get_banner(self._config.ftp.banner))

            # Command loop
            while True:
                try:
                    line = await asyncio.wait_for(
                        self._reader.readline(),
                        timeout=300,  # 5 minute timeout
                    )
                except asyncio.TimeoutError:
                    await self._send("421 Timeout.")
                    break

                if not line:
                    break

                try:
                    command_line = line.decode("utf-8", errors="replace").strip()
                except Exception:
                    continue

                if not command_line:
                    continue

                # Parse command
                parts = command_line.split(" ", 1)
                cmd = parts[0].upper()
                args = parts[1] if len(parts) > 1 else ""

                self._honeypot._logger.debug(
                    "ftp_command",
                    source_ip=self._source_ip,
                    command=cmd,
                    args=args[:100] if args else None,
                    session_id=self._session_id,
                )

                # Handle command
                try:
                    handler = self._get_command_handler(cmd)
                    if handler:
                        should_continue = await handler(args)
                        if not should_continue:
                            break
                    else:
                        await self._send(FTPTemplates.get_response("unknown"))
                except Exception as e:
                    self._honeypot._logger.error(
                        "ftp_command_error",
                        command=cmd,
                        error=str(e),
                    )
                    await self._send("500 Error processing command.")

        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            # Cleanup
            await self._cleanup_data_connection()
            await session_mgr.close_session(self._session_id)

            self._honeypot._logger.info(
                "ftp_connection_closed",
                source_ip=self._source_ip,
                session_id=self._session_id,
            )

            self._writer.close()
            try:
                await self._writer.wait_closed()
            except Exception:
                pass

    async def _send(self, message: str) -> None:
        """Send a response to the client."""
        try:
            self._writer.write(f"{message}\r\n".encode())
            await self._writer.drain()
        except Exception:
            pass

    def _get_command_handler(self, cmd: str):
        """Get handler for FTP command."""
        handlers = {
            "USER": self._cmd_user,
            "PASS": self._cmd_pass,
            "SYST": self._cmd_syst,
            "FEAT": self._cmd_feat,
            "PWD": self._cmd_pwd,
            "XPWD": self._cmd_pwd,
            "CWD": self._cmd_cwd,
            "XCWD": self._cmd_cwd,
            "CDUP": self._cmd_cdup,
            "TYPE": self._cmd_type,
            "PASV": self._cmd_pasv,
            "PORT": self._cmd_port,
            "LIST": self._cmd_list,
            "NLST": self._cmd_nlst,
            "RETR": self._cmd_retr,
            "STOR": self._cmd_stor,
            "DELE": self._cmd_dele,
            "MKD": self._cmd_mkd,
            "XMKD": self._cmd_mkd,
            "RMD": self._cmd_rmd,
            "XRMD": self._cmd_rmd,
            "SIZE": self._cmd_size,
            "MDTM": self._cmd_mdtm,
            "NOOP": self._cmd_noop,
            "QUIT": self._cmd_quit,
            "ABOR": self._cmd_abor,
        }
        return handlers.get(cmd)

    async def _cmd_user(self, args: str) -> bool:
        """Handle USER command."""
        self._username = args.strip()
        self._authenticated = False

        self._honeypot._logger.info(
            "ftp_user",
            source_ip=self._source_ip,
            username=self._username,
            session_id=self._session_id,
        )

        await self._send(FTPTemplates.get_response("user_ok"))
        return True

    async def _cmd_pass(self, args: str) -> bool:
        """Handle PASS command."""
        password = args.strip()
        session_mgr = get_session_manager()

        await session_mgr.record_auth_attempt(self._session_id)

        # Check if we should allow login
        allow_anonymous = (
            self._config.ftp.anonymous_enabled
            and self._username.lower() in ("anonymous", "ftp")
        )
        allow_login = self._username in self._config.ssh.fake_users

        success = allow_anonymous or allow_login

        # Record attack
        attack = await self._honeypot._record_attack(
            source_ip=self._source_ip,
            source_port=self._source_port,
            attack_type="brute_force" if not success else "credential_test",
            severity=3 if success else 2,
        )
        self._attack_id = attack.id

        # Record credentials
        await self._honeypot._record_credential(
            attack_id=attack.id,
            username=self._username or "unknown",
            password=password,
            auth_method="password",
            success=success,
        )

        self._honeypot._logger.credential_attempt(
            source_ip=self._source_ip,
            username=self._username or "unknown",
            success=success,
            session_id=self._session_id,
        )

        if success:
            self._authenticated = True
            await session_mgr.set_authenticated(self._session_id, self._username)
            await self._send(FTPTemplates.get_response("login_ok"))
        else:
            await self._send(FTPTemplates.get_response("login_fail"))

        return True

    async def _cmd_syst(self, args: str) -> bool:
        """Handle SYST command."""
        await self._send(FTPTemplates.get_response("syst"))
        return True

    async def _cmd_feat(self, args: str) -> bool:
        """Handle FEAT command."""
        await self._send(FTPTemplates.get_response("feat"))
        return True

    async def _cmd_pwd(self, args: str) -> bool:
        """Handle PWD command."""
        if not self._authenticated:
            await self._send(FTPTemplates.get_response("not_logged_in"))
            return True

        await self._send(FTPTemplates.get_response("pwd", path=self._fs.getcwd()))
        return True

    async def _cmd_cwd(self, args: str) -> bool:
        """Handle CWD command."""
        if not self._authenticated:
            await self._send(FTPTemplates.get_response("not_logged_in"))
            return True

        path = args.strip() or "/"
        if self._fs.chdir(path):
            await self._send(FTPTemplates.get_response("cwd_ok"))
        else:
            await self._send(FTPTemplates.get_response("cwd_fail"))

        return True

    async def _cmd_cdup(self, args: str) -> bool:
        """Handle CDUP command."""
        return await self._cmd_cwd("..")

    async def _cmd_type(self, args: str) -> bool:
        """Handle TYPE command."""
        type_code = args.strip().upper()
        if type_code in ("A", "I"):
            self._transfer_type = type_code
            mode = "ASCII" if type_code == "A" else "Binary"
            await self._send(FTPTemplates.get_response("type", mode=mode))
        else:
            await self._send("504 Command not implemented for that parameter.")

        return True

    async def _cmd_pasv(self, args: str) -> bool:
        """Handle PASV command."""
        if not self._authenticated:
            await self._send(FTPTemplates.get_response("not_logged_in"))
            return True

        await self._cleanup_data_connection()

        # Find available port in passive range
        min_port, max_port = self._config.ftp.passive_ports
        port = None

        for p in range(min_port, max_port + 1):
            try:
                server = await asyncio.start_server(
                    self._handle_data_connection,
                    "0.0.0.0",
                    p,
                )
                self._data_server = server
                port = p
                break
            except OSError:
                continue

        if port is None:
            await self._send("425 Can't open data connection.")
            return True

        self._passive_mode = True

        # Format address for PASV response
        host = self._writer.get_extra_info("sockname", ("127.0.0.1", 0))[0]
        if host == "0.0.0.0":
            host = "127.0.0.1"

        h1, h2, h3, h4 = host.split(".")
        p1, p2 = port >> 8, port & 0xFF

        await self._send(
            FTPTemplates.get_response("pasv", addr=f"{h1},{h2},{h3},{h4},{p1},{p2}")
        )
        return True

    async def _cmd_port(self, args: str) -> bool:
        """Handle PORT command (active mode)."""
        if not self._authenticated:
            await self._send(FTPTemplates.get_response("not_logged_in"))
            return True

        try:
            parts = args.strip().split(",")
            if len(parts) != 6:
                raise ValueError("Invalid PORT format")

            host = ".".join(parts[:4])
            port = (int(parts[4]) << 8) + int(parts[5])

            self._passive_mode = False
            self._data_host = host
            self._data_port = port

            await self._send(FTPTemplates.get_response("port"))
        except Exception:
            await self._send("501 Syntax error in parameters.")

        return True

    async def _handle_data_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle incoming data connection for passive mode."""
        self._data_connection = (reader, writer)

    async def _get_data_connection(self) -> Optional[tuple]:
        """Get or establish data connection."""
        if self._passive_mode:
            # Wait for client to connect
            for _ in range(50):  # 5 second timeout
                if self._data_connection:
                    return self._data_connection
                await asyncio.sleep(0.1)
            return None
        else:
            # Active mode - connect to client
            try:
                reader, writer = await asyncio.open_connection(
                    self._data_host,
                    self._data_port,
                )
                return (reader, writer)
            except Exception:
                return None

    async def _cleanup_data_connection(self) -> None:
        """Clean up data connection resources."""
        if self._data_server:
            self._data_server.close()
            try:
                await self._data_server.wait_closed()
            except Exception:
                pass
            self._data_server = None

        if self._data_connection:
            _, writer = self._data_connection
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            self._data_connection = None

    async def _cmd_list(self, args: str) -> bool:
        """Handle LIST command."""
        if not self._authenticated:
            await self._send(FTPTemplates.get_response("not_logged_in"))
            return True

        path = args.strip() or "."

        await self._send(FTPTemplates.get_response("list_start"))

        conn = await self._get_data_connection()
        if conn:
            reader, writer = conn
            try:
                # Generate directory listing
                listing = self._generate_listing(path)
                writer.write(listing.encode())
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()
                await self._cleanup_data_connection()

            await self._send(FTPTemplates.get_response("list_end"))
        else:
            await self._send("425 Can't open data connection.")

        return True

    async def _cmd_nlst(self, args: str) -> bool:
        """Handle NLST command (name list only)."""
        if not self._authenticated:
            await self._send(FTPTemplates.get_response("not_logged_in"))
            return True

        path = args.strip() or "."

        await self._send(FTPTemplates.get_response("list_start"))

        conn = await self._get_data_connection()
        if conn:
            reader, writer = conn
            try:
                entries = self._fs.listdir(path)
                listing = "\r\n".join(entries) + "\r\n"
                writer.write(listing.encode())
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()
                await self._cleanup_data_connection()

            await self._send(FTPTemplates.get_response("list_end"))
        else:
            await self._send("425 Can't open data connection.")

        return True

    def _generate_listing(self, path: str) -> str:
        """Generate directory listing in ls -l format."""
        lines = []
        entries = self._fs.listdir(path)

        for name in entries:
            full_path = f"{path}/{name}" if path != "." else name
            node = self._fs.stat(full_path)
            if node:
                line = FTPTemplates.format_list_entry(
                    name=name,
                    is_dir=node.is_dir(),
                    size=node.size,
                    owner=node.owner,
                    group=node.group,
                    perms=node.permissions,
                )
                lines.append(line)

        return "\r\n".join(lines) + "\r\n"

    async def _cmd_retr(self, args: str) -> bool:
        """Handle RETR command (download)."""
        if not self._authenticated:
            await self._send(FTPTemplates.get_response("not_logged_in"))
            return True

        filename = args.strip()
        session_mgr = get_session_manager()

        if not self._fs.is_file(filename):
            await self._send(FTPTemplates.get_response("file_not_found", file=filename))
            return True

        try:
            content = self._fs.read_file(filename)
            await session_mgr.record_file_download(self._session_id, len(content))

            self._honeypot._logger.info(
                "ftp_download",
                source_ip=self._source_ip,
                filename=filename,
                size=len(content),
                session_id=self._session_id,
            )

            await self._send(
                FTPTemplates.get_response("retr_start", file=filename, size=len(content))
            )

            conn = await self._get_data_connection()
            if conn:
                reader, writer = conn
                try:
                    writer.write(content)
                    await writer.drain()
                finally:
                    writer.close()
                    await writer.wait_closed()
                    await self._cleanup_data_connection()

                await self._send(FTPTemplates.get_response("retr_end"))
            else:
                await self._send("425 Can't open data connection.")

        except FileNotFoundError:
            await self._send(FTPTemplates.get_response("file_not_found", file=filename))

        return True

    async def _cmd_stor(self, args: str) -> bool:
        """Handle STOR command (upload)."""
        if not self._authenticated:
            await self._send(FTPTemplates.get_response("not_logged_in"))
            return True

        filename = args.strip()
        session_mgr = get_session_manager()

        await self._send(FTPTemplates.get_response("stor_start"))

        conn = await self._get_data_connection()
        if conn:
            reader, writer = conn
            try:
                # Read uploaded data
                content = await reader.read()

                await session_mgr.record_file_upload(self._session_id, len(content))

                self._honeypot._logger.warning(
                    "ftp_upload",
                    source_ip=self._source_ip,
                    filename=filename,
                    size=len(content),
                    session_id=self._session_id,
                )

                # Save to quarantine
                safe_filename = hashlib.sha256(
                    f"{self._source_ip}_{filename}_{datetime.now().isoformat()}".encode()
                ).hexdigest()[:16]
                save_path = self._upload_dir / f"{safe_filename}_{filename}"

                with open(save_path, "wb") as f:
                    f.write(content)

                # Record in database
                if self._attack_id is None:
                    attack = await self._honeypot._record_attack(
                        source_ip=self._source_ip,
                        source_port=self._source_port,
                        attack_type="file_upload",
                        severity=7,
                    )
                    self._attack_id = attack.id

                await self._honeypot._record_file(
                    attack_id=self._attack_id,
                    filename=filename,
                    content=content,
                    operation="upload",
                    original_path=self._fs.getcwd() + "/" + filename,
                )

            finally:
                writer.close()
                await writer.wait_closed()
                await self._cleanup_data_connection()

            await self._send(FTPTemplates.get_response("stor_end"))
        else:
            await self._send("425 Can't open data connection.")

        return True

    async def _cmd_dele(self, args: str) -> bool:
        """Handle DELE command (delete)."""
        if not self._authenticated:
            await self._send(FTPTemplates.get_response("not_logged_in"))
            return True

        await self._send(FTPTemplates.get_response("permission_denied"))
        return True

    async def _cmd_mkd(self, args: str) -> bool:
        """Handle MKD command (make directory)."""
        if not self._authenticated:
            await self._send(FTPTemplates.get_response("not_logged_in"))
            return True

        await self._send(FTPTemplates.get_response("permission_denied"))
        return True

    async def _cmd_rmd(self, args: str) -> bool:
        """Handle RMD command (remove directory)."""
        if not self._authenticated:
            await self._send(FTPTemplates.get_response("not_logged_in"))
            return True

        await self._send(FTPTemplates.get_response("permission_denied"))
        return True

    async def _cmd_size(self, args: str) -> bool:
        """Handle SIZE command."""
        if not self._authenticated:
            await self._send(FTPTemplates.get_response("not_logged_in"))
            return True

        filename = args.strip()
        node = self._fs.stat(filename)

        if node and node.is_file():
            await self._send(f"213 {node.size}")
        else:
            await self._send(FTPTemplates.get_response("file_not_found", file=filename))

        return True

    async def _cmd_mdtm(self, args: str) -> bool:
        """Handle MDTM command (modification time)."""
        if not self._authenticated:
            await self._send(FTPTemplates.get_response("not_logged_in"))
            return True

        filename = args.strip()
        node = self._fs.stat(filename)

        if node:
            mtime = node.mtime.strftime("%Y%m%d%H%M%S")
            await self._send(f"213 {mtime}")
        else:
            await self._send(FTPTemplates.get_response("file_not_found", file=filename))

        return True

    async def _cmd_noop(self, args: str) -> bool:
        """Handle NOOP command."""
        await self._send(FTPTemplates.get_response("noop"))
        return True

    async def _cmd_quit(self, args: str) -> bool:
        """Handle QUIT command."""
        await self._send(FTPTemplates.get_response("quit"))
        return False

    async def _cmd_abor(self, args: str) -> bool:
        """Handle ABOR command."""
        await self._cleanup_data_connection()
        await self._send("226 Abort successful.")
        return True


class FTPHoneypot(BaseHoneypotService):
    """
    FTP Honeypot Service.
    
    Implements a high-interaction FTP honeypot that captures credentials,
    file uploads, and logs all FTP commands.
    """

    def __init__(self, config: Config):
        super().__init__(config)
        self._server: Optional[asyncio.Server] = None

    @property
    def service_name(self) -> str:
        return "ftp"

    @property
    def port(self) -> int:
        return self._config.ftp.port

    @property
    def protocol(self) -> str:
        return "TCP"

    async def start(self) -> None:
        """Start the FTP honeypot server."""
        if self._running:
            return

        try:
            self._server = await asyncio.start_server(
                self._handle_client,
                self._config.ftp.host,
                self._config.ftp.port,
            )

            self._running = True
            self._logger.info(
                "ftp_honeypot_started",
                host=self._config.ftp.host,
                port=self._config.ftp.port,
            )

        except Exception as e:
            self._logger.error("ftp_honeypot_start_failed", error=str(e))
            raise

    async def stop(self) -> None:
        """Stop the FTP honeypot server."""
        if not self._running:
            return

        self._running = False

        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

        self._logger.info("ftp_honeypot_stopped")

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle incoming FTP client connection."""
        handler = FTPClientHandler(self, reader, writer)
        await handler.handle()

    async def handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle connection (delegates to _handle_client)."""
        await self._handle_client(reader, writer)
