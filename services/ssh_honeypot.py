"""
SSH Honeypot Service

High-interaction SSH honeypot using asyncssh library.
Captures credentials, emulates shell environment, and logs all commands.
"""

from __future__ import annotations

import asyncio
import os
import shlex
from datetime import datetime
from pathlib import Path
from typing import Optional

import asyncssh
from asyncssh import SSHKey
from asyncssh.misc import MaybeAwait

from core.base_service import BaseHoneypotService
from core.config import Config
from core.logger import ServiceLogger
from services.utils.fake_filesystem import FakeFilesystem
from services.utils.response_templates import ShellTemplates, SSHTemplates
from services.utils.session_manager import SessionManager, SessionState, get_session_manager


class SSHServerProtocol(asyncssh.SSHServer):
    """SSH server protocol handler for the honeypot."""

    def __init__(self, honeypot: "SSHHoneypot"):
        self._honeypot = honeypot
        self._username: Optional[str] = None
        self._session_id: Optional[str] = None
        self._conn: Optional[asyncssh.SSHServerConnection] = None
        self._peername: tuple[str, int] = ("unknown", 0)

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        """Called when connection is established."""
        self._conn = conn
        peername = conn.get_extra_info("peername")
        if peername:
            self._peername = (peername[0], peername[1])

        self._honeypot._logger.connection(
            source_ip=self._peername[0],
            source_port=self._peername[1],
            event="ssh_connection_made",
        )

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """Called when connection is closed."""
        self._honeypot._logger.info(
            "ssh_connection_lost",
            source_ip=self._peername[0],
            session_id=self._session_id,
            error=str(exc) if exc else None,
        )

    def begin_auth(self, username: str) -> MaybeAwait[bool]:
        """Called when authentication begins."""
        self._username = username
        self._honeypot._logger.info(
            "ssh_auth_begin",
            source_ip=self._peername[0],
            username=username,
        )
        return True

    def password_auth_supported(self) -> bool:
        """Allow password authentication."""
        return True

    def public_key_auth_supported(self) -> bool:
        """Allow public key authentication attempts (always fail)."""
        return True

    async def validate_password(self, username: str, password: str) -> bool:
        """
        Validate password and capture credentials.
        
        Returns True for configured allowed credentials to enable
        deeper interaction logging.
        """
        session_mgr = get_session_manager()

        if not self._session_id:
            session = await session_mgr.create_session(
                source_ip=self._peername[0],
                source_port=self._peername[1],
                service_type="ssh",
            )
            self._session_id = session.session_id

        await session_mgr.record_auth_attempt(self._session_id)

        # Check if credentials should allow login
        config = self._honeypot._config
        allowed = (
            username in config.ssh.fake_users
            and password in config.ssh.allowed_passwords
        )

        # Record the attack
        attack = await self._honeypot._record_attack(
            source_ip=self._peername[0],
            source_port=self._peername[1],
            attack_type="brute_force" if not allowed else "credential_test",
            severity=3 if allowed else 2,
        )

        # Record credentials
        await self._honeypot._record_credential(
            attack_id=attack.id,
            username=username,
            password=password,
            auth_method="password",
            success=allowed,
        )

        self._honeypot._logger.credential_attempt(
            source_ip=self._peername[0],
            username=username,
            success=allowed,
            session_id=self._session_id,
        )

        if allowed:
            await session_mgr.set_authenticated(self._session_id, username)

        return allowed

    async def validate_public_key(self, username: str, key: SSHKey) -> bool:
        """Always reject public key auth but log the attempt."""
        self._honeypot._logger.info(
            "ssh_pubkey_attempt",
            source_ip=self._peername[0],
            username=username,
            key_type=key.algorithm if hasattr(key, "algorithm") else "unknown",
        )
        return False


class SSHSessionHandler(asyncssh.SSHServerProcess):
    """Handles an authenticated SSH session with shell emulation."""

    def __init__(
        self,
        honeypot: "SSHHoneypot",
        session_id: str,
        username: str,
        source_ip: str,
    ):
        self._honeypot = honeypot
        self._session_id = session_id
        self._username = username
        self._source_ip = source_ip
        self._fs = FakeFilesystem()
        self._env: dict[str, str] = {
            "USER": username,
            "HOME": f"/home/{username}" if username != "root" else "/root",
            "SHELL": "/bin/bash",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "PWD": f"/home/{username}" if username != "root" else "/root",
            "TERM": "xterm-256color",
        }
        self._attack_id: Optional[int] = None

        # Set initial directory
        home = self._env["HOME"]
        if self._fs.is_dir(home):
            self._fs.chdir(home)

    def _get_prompt(self) -> str:
        """Generate shell prompt."""
        cwd = self._fs.getcwd()
        if cwd == self._env["HOME"]:
            cwd = "~"
        elif cwd.startswith(self._env["HOME"]):
            cwd = "~" + cwd[len(self._env["HOME"]):]

        prompt_char = "#" if self._username == "root" else "$"
        return f"{self._username}@ubuntu-server:{cwd}{prompt_char} "

    async def _execute_command(self, cmd_line: str) -> str:
        """Execute a command and return output."""
        cmd_line = cmd_line.strip()
        if not cmd_line:
            return ""

        # Record command
        session_mgr = get_session_manager()
        await session_mgr.record_command(self._session_id)

        try:
            parts = shlex.split(cmd_line)
        except ValueError:
            parts = cmd_line.split()

        if not parts:
            return ""

        cmd = parts[0]
        args = parts[1:] if len(parts) > 1 else []
        args_str = " ".join(args)

        # Determine if command is malicious
        is_malicious = self._is_malicious_command(cmd, args_str)

        # Create attack record if not exists
        if self._attack_id is None:
            attack = await self._honeypot._record_attack(
                source_ip=self._source_ip,
                source_port=0,
                attack_type="command_execution",
                severity=5 if is_malicious else 2,
            )
            self._attack_id = attack.id

        # Record command in database
        output = self._handle_command(cmd, args)

        await self._honeypot._record_command(
            attack_id=self._attack_id,
            command=cmd,
            arguments=args_str if args_str else None,
            command_type=self._classify_command(cmd),
            is_malicious=is_malicious,
            working_directory=self._fs.getcwd(),
            output=output[:1000] if output else None,
            exit_code=0,
        )

        self._honeypot._logger.info(
            "ssh_command",
            source_ip=self._source_ip,
            session_id=self._session_id,
            command=cmd_line,
            is_malicious=is_malicious,
        )

        return output

    def _handle_command(self, cmd: str, args: list[str]) -> str:
        """Handle individual commands with realistic responses."""
        handlers = {
            "ls": self._cmd_ls,
            "cd": self._cmd_cd,
            "pwd": self._cmd_pwd,
            "whoami": self._cmd_whoami,
            "id": self._cmd_id,
            "uname": self._cmd_uname,
            "cat": self._cmd_cat,
            "echo": self._cmd_echo,
            "ps": self._cmd_ps,
            "netstat": self._cmd_netstat,
            "w": self._cmd_w,
            "hostname": self._cmd_hostname,
            "exit": self._cmd_exit,
            "logout": self._cmd_exit,
            "clear": self._cmd_clear,
            "history": self._cmd_history,
            "wget": self._cmd_wget,
            "curl": self._cmd_curl,
            "chmod": self._cmd_chmod,
            "mkdir": self._cmd_mkdir,
            "rm": self._cmd_rm,
            "touch": self._cmd_touch,
            "head": self._cmd_head,
            "tail": self._cmd_tail,
            "grep": self._cmd_grep,
            "find": self._cmd_find,
            "env": self._cmd_env,
            "export": self._cmd_export,
            "unset": self._cmd_unset,
        }

        handler = handlers.get(cmd)
        if handler:
            return handler(args)

        return ShellTemplates.get_unknown_command(cmd)

    def _cmd_ls(self, args: list[str]) -> str:
        long_format = "-l" in args or "-la" in args or "-al" in args
        show_all = "-a" in args or "-la" in args or "-al" in args
        path = next((a for a in args if not a.startswith("-")), ".")
        return self._fs.ls(path, long_format=long_format, show_all=show_all)

    def _cmd_cd(self, args: list[str]) -> str:
        path = args[0] if args else self._env["HOME"]
        if path == "-":
            path = self._env.get("OLDPWD", self._env["HOME"])

        old_pwd = self._fs.getcwd()
        if self._fs.chdir(path):
            self._env["OLDPWD"] = old_pwd
            self._env["PWD"] = self._fs.getcwd()
            return ""
        return f"-bash: cd: {path}: No such file or directory"

    def _cmd_pwd(self, args: list[str]) -> str:
        return self._fs.getcwd()

    def _cmd_whoami(self, args: list[str]) -> str:
        return self._username

    def _cmd_id(self, args: list[str]) -> str:
        uid = 0 if self._username == "root" else 1000
        return ShellTemplates.get_id(self._username, uid, uid)

    def _cmd_uname(self, args: list[str]) -> str:
        return ShellTemplates.get_uname(" ".join(args))

    def _cmd_cat(self, args: list[str]) -> str:
        if not args:
            return ""
        results = []
        for path in args:
            try:
                content = self._fs.read_file(path)
                results.append(content.decode("utf-8", errors="replace"))
            except FileNotFoundError:
                results.append(f"cat: {path}: No such file or directory")
        return "\n".join(results)

    def _cmd_echo(self, args: list[str]) -> str:
        text = " ".join(args)
        # Handle environment variable expansion
        for key, value in self._env.items():
            text = text.replace(f"${key}", value)
            text = text.replace(f"${{{key}}}", value)
        return text

    def _cmd_ps(self, args: list[str]) -> str:
        return ShellTemplates.get_ps(self._username)

    def _cmd_netstat(self, args: list[str]) -> str:
        return ShellTemplates.get_netstat()

    def _cmd_w(self, args: list[str]) -> str:
        return ShellTemplates.get_w(self._username, self._source_ip)

    def _cmd_hostname(self, args: list[str]) -> str:
        return "ubuntu-server"

    def _cmd_exit(self, args: list[str]) -> str:
        raise SystemExit()

    def _cmd_clear(self, args: list[str]) -> str:
        return "\033[2J\033[H"

    def _cmd_history(self, args: list[str]) -> str:
        return "    1  ls -la\n    2  cd /var/log\n    3  cat auth.log"

    def _cmd_wget(self, args: list[str]) -> str:
        if not args:
            return "wget: missing URL"
        url = args[-1]
        self._honeypot._logger.warning(
            "ssh_download_attempt",
            source_ip=self._source_ip,
            session_id=self._session_id,
            url=url,
            tool="wget",
        )
        return f"--{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}--  {url}\nResolving failed: Name or service not known.\nwget: unable to resolve host address"

    def _cmd_curl(self, args: list[str]) -> str:
        url = next((a for a in args if not a.startswith("-")), None)
        if not url:
            return "curl: no URL specified!"
        self._honeypot._logger.warning(
            "ssh_download_attempt",
            source_ip=self._source_ip,
            session_id=self._session_id,
            url=url,
            tool="curl",
        )
        return f"curl: (6) Could not resolve host: {url.split('/')[2] if '/' in url else url}"

    def _cmd_chmod(self, args: list[str]) -> str:
        if len(args) < 2:
            return "chmod: missing operand"
        return ""

    def _cmd_mkdir(self, args: list[str]) -> str:
        if not args:
            return "mkdir: missing operand"
        return ""

    def _cmd_rm(self, args: list[str]) -> str:
        if not args:
            return "rm: missing operand"
        return ""

    def _cmd_touch(self, args: list[str]) -> str:
        if not args:
            return "touch: missing file operand"
        return ""

    def _cmd_head(self, args: list[str]) -> str:
        path = next((a for a in args if not a.startswith("-")), None)
        if not path:
            return ""
        try:
            content = self._fs.read_file(path).decode("utf-8", errors="replace")
            lines = content.split("\n")[:10]
            return "\n".join(lines)
        except FileNotFoundError:
            return f"head: cannot open '{path}' for reading: No such file or directory"

    def _cmd_tail(self, args: list[str]) -> str:
        path = next((a for a in args if not a.startswith("-")), None)
        if not path:
            return ""
        try:
            content = self._fs.read_file(path).decode("utf-8", errors="replace")
            lines = content.split("\n")[-10:]
            return "\n".join(lines)
        except FileNotFoundError:
            return f"tail: cannot open '{path}' for reading: No such file or directory"

    def _cmd_grep(self, args: list[str]) -> str:
        if len(args) < 2:
            return "Usage: grep [OPTION]... PATTERN [FILE]..."
        return ""

    def _cmd_find(self, args: list[str]) -> str:
        return ""

    def _cmd_env(self, args: list[str]) -> str:
        return "\n".join(f"{k}={v}" for k, v in self._env.items())

    def _cmd_export(self, args: list[str]) -> str:
        for arg in args:
            if "=" in arg:
                key, value = arg.split("=", 1)
                self._env[key] = value
        return ""

    def _cmd_unset(self, args: list[str]) -> str:
        for arg in args:
            self._env.pop(arg, None)
        return ""

    def _is_malicious_command(self, cmd: str, args: str) -> bool:
        """Check if command appears malicious."""
        malicious_patterns = [
            "wget", "curl", "nc", "netcat", "ncat",
            "/dev/tcp", "/dev/udp",
            "base64", "python", "perl", "ruby", "php",
            "chmod +x", "chmod 777",
            "/tmp/", "/var/tmp/", "/dev/shm/",
            "crontab", "at ",
            "useradd", "adduser", "passwd",
            "iptables", "ufw",
        ]
        full_cmd = f"{cmd} {args}".lower()
        return any(p in full_cmd for p in malicious_patterns)

    def _classify_command(self, cmd: str) -> str:
        """Classify command type."""
        categories = {
            "recon": ["ls", "cat", "find", "grep", "ps", "netstat", "w", "who", "id", "uname", "hostname"],
            "download": ["wget", "curl", "scp", "sftp", "ftp"],
            "persistence": ["crontab", "at", "useradd", "adduser"],
            "lateral_movement": ["ssh", "telnet", "nc", "netcat"],
            "privilege_escalation": ["sudo", "su", "chmod", "chown"],
            "data_exfil": ["tar", "zip", "gzip", "base64"],
        }
        for category, commands in categories.items():
            if cmd in commands:
                return category
        return "other"


class SSHHoneypot(BaseHoneypotService):
    """
    SSH Honeypot Service.
    
    Implements a high-interaction SSH honeypot that captures credentials,
    emulates a shell environment, and logs all attacker activity.
    """

    def __init__(self, config: Config):
        super().__init__(config)
        self._server: Optional[asyncssh.SSHAcceptor] = None
        self._host_key_path: Optional[str] = None

    @property
    def service_name(self) -> str:
        return "ssh"

    @property
    def port(self) -> int:
        return self._config.ssh.port

    @property
    def protocol(self) -> str:
        return "TCP"

    async def start(self) -> None:
        """Start the SSH honeypot server."""
        if self._running:
            return

        # Generate or load host key
        await self._ensure_host_key()

        try:
            self._server = await asyncssh.create_server(
                lambda: SSHServerProtocol(self),
                self._config.ssh.host,
                self._config.ssh.port,
                server_host_keys=[self._host_key_path],
                process_factory=self._create_process,
                login_timeout=self._config.ssh.login_timeout,
            )

            self._running = True
            self._logger.info(
                "ssh_honeypot_started",
                host=self._config.ssh.host,
                port=self._config.ssh.port,
            )

        except Exception as e:
            self._logger.error("ssh_honeypot_start_failed", error=str(e))
            raise

    async def stop(self) -> None:
        """Stop the SSH honeypot server."""
        if not self._running:
            return

        self._running = False

        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

        self._logger.info("ssh_honeypot_stopped")

    async def handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Not used - asyncssh handles connections internally."""
        pass

    async def _ensure_host_key(self) -> None:
        """Ensure SSH host key exists, generate if needed."""
        key_path = self._config.ssh.host_key_path

        if key_path and os.path.exists(key_path):
            self._host_key_path = key_path
            return

        # Generate a new host key
        key_dir = Path("data/ssh_keys")
        key_dir.mkdir(parents=True, exist_ok=True)
        key_path = str(key_dir / "ssh_host_rsa_key")

        if not os.path.exists(key_path):
            self._logger.info("generating_ssh_host_key", path=key_path)
            key = asyncssh.generate_private_key("ssh-rsa", 2048)
            key.write_private_key(key_path)
            os.chmod(key_path, 0o600)

        self._host_key_path = key_path

    def _create_process(
        self,
        process: asyncssh.SSHServerProcess,
    ) -> SSHSessionHandler:
        """Create a new session handler for an authenticated user."""
        conn = process.channel.get_connection()
        peername = conn.get_extra_info("peername", ("unknown", 0))

        # Get session info from the protocol
        username = process.get_extra_info("username", "unknown")

        session_id = str(id(process))

        self._logger.info(
            "ssh_session_started",
            source_ip=peername[0],
            username=username,
            session_id=session_id,
        )

        return SSHSessionHandler(
            honeypot=self,
            session_id=session_id,
            username=username,
            source_ip=peername[0],
        )


# Monkey-patch SSHSessionHandler to work as a process
async def _handle_session(handler: SSHSessionHandler) -> None:
    """Handle the SSH session loop."""
    process = handler
    stdin = process.stdin
    stdout = process.stdout
    stderr = process.stderr

    # Send MOTD
    stdout.write(SSHTemplates.get_motd(handler._source_ip))
    stdout.write("\n")

    try:
        while True:
            # Send prompt
            prompt = handler._get_prompt()
            stdout.write(prompt)
            await stdout.drain()

            # Read command
            try:
                line = await stdin.readline()
                if not line:
                    break

                cmd = line.rstrip("\n\r")
                if not cmd:
                    continue

                # Execute command
                try:
                    output = await handler._execute_command(cmd)
                    if output:
                        stdout.write(output)
                        if not output.endswith("\n"):
                            stdout.write("\n")
                except SystemExit:
                    stdout.write("logout\n")
                    break

            except asyncssh.BreakReceived:
                stdout.write("^C\n")
            except asyncssh.TerminalSizeChanged:
                pass

    except (asyncssh.ConnectionLost, BrokenPipeError):
        pass
    finally:
        handler._honeypot._logger.info(
            "ssh_session_ended",
            source_ip=handler._source_ip,
            session_id=handler._session_id,
        )
        process.exit(0)


# Override the SSHSessionHandler to be callable as a coroutine
SSHSessionHandler.__call__ = lambda self: _handle_session(self)
