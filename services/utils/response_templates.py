"""
Response Templates Module

Realistic service banners, error messages, and response templates
for honeypot services to simulate real systems convincingly.
"""

from __future__ import annotations

import random
from datetime import datetime
from typing import Optional


class SSHTemplates:
    """SSH server response templates."""

    BANNERS = [
        "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4",
        "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
        "SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2",
        "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1",
        "SSH-2.0-OpenSSH_7.4",
        "SSH-2.0-OpenSSH_8.0",
    ]

    MOTD = """Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-89-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of {date}

  System load:  0.08              Processes:             124
  Usage of /:   23.1% of 48.27GB  Users logged in:       0
  Memory usage: 12%               IPv4 address for eth0: 192.168.1.10
  Swap usage:   0%

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, secure and portable Kubernetes cluster
   deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status

Last login: {last_login} from {last_ip}
"""

    AUTH_FAILED_MESSAGES = [
        "Permission denied, please try again.",
        "Permission denied (publickey,password).",
        "Access denied",
    ]

    @classmethod
    def get_banner(cls, custom: Optional[str] = None) -> str:
        """Get SSH banner string."""
        return custom or random.choice(cls.BANNERS)

    @classmethod
    def get_motd(cls, last_ip: str = "192.168.1.100") -> str:
        """Get Message of the Day."""
        now = datetime.now()
        return cls.MOTD.format(
            date=now.strftime("%a %b %d %H:%M:%S UTC %Y"),
            last_login=now.strftime("%a %b %d %H:%M:%S %Y"),
            last_ip=last_ip,
        )

    @classmethod
    def get_auth_failed(cls) -> str:
        """Get authentication failure message."""
        return random.choice(cls.AUTH_FAILED_MESSAGES)


class ShellTemplates:
    """Shell command response templates."""

    UNAME_RESPONSES = {
        "uname": "Linux",
        "uname -a": "Linux ubuntu-server 5.15.0-89-generic #99-Ubuntu SMP Mon Oct 30 20:42:41 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux",
        "uname -r": "5.15.0-89-generic",
        "uname -n": "ubuntu-server",
        "uname -m": "x86_64",
        "uname -s": "Linux",
        "uname -o": "GNU/Linux",
    }

    ID_RESPONSE = "uid={uid}({user}) gid={gid}({group}) groups={gid}({group})"

    WHOAMI_RESPONSE = "{user}"

    HOSTNAME_RESPONSE = "ubuntu-server"

    UPTIME_RESPONSE = " {time} up {days} days, {hours}:{mins},  1 user,  load average: 0.00, 0.01, 0.05"

    PS_HEADER = "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"

    PS_ENTRIES = [
        "root           1  0.0  0.1 167452 11876 ?        Ss   Oct30   0:03 /sbin/init",
        "root           2  0.0  0.0      0     0 ?        S    Oct30   0:00 [kthreadd]",
        "root         456  0.0  0.1  17220  9012 ?        Ss   Oct30   0:00 /lib/systemd/systemd-logind",
        "root         789  0.0  0.0  15420  7124 ?        Ss   Oct30   0:00 sshd: /usr/sbin/sshd -D",
        "root        1234  0.0  0.1  17960 10284 ?        Ss   {time}   0:00 sshd: {user} [priv]",
        "{user}      1235  0.0  0.0  18096  7512 ?        S    {time}   0:00 sshd: {user}@pts/0",
        "{user}      1236  0.0  0.0   8276  5164 pts/0    Ss   {time}   0:00 -bash",
        "{user}      1337  0.0  0.0  10072  3384 pts/0    R+   {time}   0:00 ps aux",
    ]

    NETSTAT_HEADER = "Active Internet connections (only servers)"
    NETSTAT_COLUMNS = "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name"
    NETSTAT_ENTRIES = [
        "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      789/sshd",
        "tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      1024/mysqld",
        "tcp6       0      0 :::80                   :::*                    LISTEN      2048/apache2",
        "tcp6       0      0 :::22                   :::*                    LISTEN      789/sshd",
    ]

    W_HEADER = " {time} up {days} days, {hours}:{mins},  1 user,  load average: 0.00, 0.01, 0.05"
    W_COLUMNS = "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT"
    W_ENTRY = "{user:8} pts/0    {ip:16} {time}    0.00s  0.01s  0.00s w"

    @classmethod
    def get_uname(cls, args: str = "") -> str:
        """Get uname command output."""
        cmd = f"uname {args}".strip()
        return cls.UNAME_RESPONSES.get(cmd, cls.UNAME_RESPONSES["uname -a"])

    @classmethod
    def get_id(cls, user: str = "root", uid: int = 0, gid: int = 0) -> str:
        """Get id command output."""
        return cls.ID_RESPONSE.format(uid=uid, user=user, gid=gid, group=user)

    @classmethod
    def get_ps(cls, user: str = "root") -> str:
        """Get ps aux output."""
        now = datetime.now().strftime("%H:%M")
        lines = [cls.PS_HEADER]
        for entry in cls.PS_ENTRIES:
            lines.append(entry.format(user=user, time=now))
        return "\n".join(lines)

    @classmethod
    def get_netstat(cls) -> str:
        """Get netstat -tlnp output."""
        lines = [cls.NETSTAT_HEADER, cls.NETSTAT_COLUMNS]
        lines.extend(cls.NETSTAT_ENTRIES)
        return "\n".join(lines)

    @classmethod
    def get_w(cls, user: str = "root", ip: str = "192.168.1.100") -> str:
        """Get w command output."""
        now = datetime.now()
        lines = [
            cls.W_HEADER.format(
                time=now.strftime("%H:%M:%S"),
                days=random.randint(1, 30),
                hours=random.randint(0, 23),
                mins=str(random.randint(0, 59)).zfill(2),
            ),
            cls.W_COLUMNS,
            cls.W_ENTRY.format(user=user, ip=ip, time=now.strftime("%H:%M")),
        ]
        return "\n".join(lines)

    @classmethod
    def get_unknown_command(cls, cmd: str) -> str:
        """Get unknown command error."""
        return f"-bash: {cmd}: command not found"


class HTTPTemplates:
    """HTTP server response templates."""

    SERVER_HEADERS = [
        "Apache/2.4.52 (Ubuntu)",
        "nginx/1.18.0 (Ubuntu)",
        "Apache/2.4.41 (Ubuntu)",
        "nginx/1.22.1",
        "Microsoft-IIS/10.0",
    ]

    ERROR_404 = """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL {path} was not found on this server.</p>
<hr>
<address>{server} Server at {host} Port {port}</address>
</body></html>
"""

    ERROR_403 = """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access {path} on this server.</p>
<hr>
<address>{server} Server at {host} Port {port}</address>
</body></html>
"""

    ERROR_500 = """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>500 Internal Server Error</title>
</head><body>
<h1>Internal Server Error</h1>
<p>The server encountered an internal error or misconfiguration and was unable to complete your request.</p>
<hr>
<address>{server} Server at {host} Port {port}</address>
</body></html>
"""

    LOGIN_PAGE = """<!DOCTYPE html>
<html>
<head>
    <title>Login - Admin Panel</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: #f4f4f4; margin: 0; padding: 50px; }}
        .login-box {{ background: white; padding: 40px; max-width: 400px; margin: 0 auto; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h2 {{ margin-bottom: 30px; color: #333; }}
        input {{ width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }}
        button {{ width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }}
        button:hover {{ background: #0056b3; }}
        .error {{ color: red; margin-bottom: 15px; }}
    </style>
</head>
<body>
    <div class="login-box">
        <h2>Administrator Login</h2>
        {error}
        <form method="POST" action="/admin/login">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
"""

    WORDPRESS_LOGIN = """<!DOCTYPE html>
<html lang="en-US">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width">
    <title>Log In &lsaquo; WordPress</title>
    <style>
        body {{ background: #f1f1f1; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif; }}
        #login {{ width: 320px; margin: 100px auto; }}
        .login form {{ background: #fff; border: 1px solid #c3c4c7; box-shadow: 0 1px 3px rgba(0,0,0,.04); padding: 26px 24px; }}
        input[type="text"], input[type="password"] {{ width: 100%; padding: 10px; margin: 5px 0 15px; border: 1px solid #8c8f94; }}
        #wp-submit {{ background: #2271b1; border: none; color: #fff; padding: 10px 20px; cursor: pointer; }}
        h1 a {{ background-image: url(data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA1MTIgNTEyIj48cGF0aCBmaWxsPSIjMDA3NWE5IiBkPSJNMjU2IDhDMTE5LjMgOCA4IDExOS4zIDggMjU2czExMS4zIDI0OCAyNDggMjQ4IDI0OC0xMTEuMyAyNDgtMjQ4UzM5Mi43IDggMjU2IDh6Ii8+PC9zdmc+); width: 84px; height: 84px; display: block; margin: 0 auto 25px; background-size: contain; }}
        .error {{ background: #d63638; color: #fff; padding: 12px; margin-bottom: 16px; }}
    </style>
</head>
<body class="login">
    <div id="login">
        <h1><a href="https://wordpress.org/">WordPress</a></h1>
        {error}
        <form name="loginform" method="post" action="/wp-login.php">
            <p>
                <label for="user_login">Username or Email Address</label>
                <input type="text" name="log" id="user_login" size="20">
            </p>
            <p>
                <label for="user_pass">Password</label>
                <input type="password" name="pwd" id="user_pass" size="20">
            </p>
            <p class="submit">
                <input type="submit" name="wp-submit" id="wp-submit" value="Log In">
            </p>
        </form>
    </div>
</body>
</html>
"""

    PHPINFO_FAKE = """<!DOCTYPE html>
<html>
<head><title>phpinfo()</title>
<style>
body {{ background: #fff; color: #000; font-family: sans-serif; }}
table {{ border-collapse: collapse; width: 600px; margin: 20px auto; }}
td, th {{ border: 1px solid #000; padding: 4px 8px; }}
.e {{ background: #ccf; font-weight: bold; }}
.v {{ background: #ddd; }}
h1 {{ text-align: center; }}
</style>
</head>
<body>
<h1>PHP Version 8.1.2-1ubuntu2.14</h1>
<table>
<tr><td class="e">System</td><td class="v">Linux ubuntu-server 5.15.0-89-generic</td></tr>
<tr><td class="e">Server API</td><td class="v">Apache 2.0 Handler</td></tr>
<tr><td class="e">Document Root</td><td class="v">/var/www/html</td></tr>
<tr><td class="e">REMOTE_ADDR</td><td class="v">{remote_addr}</td></tr>
<tr><td class="e">SERVER_SOFTWARE</td><td class="v">Apache/2.4.52 (Ubuntu)</td></tr>
</table>
</body>
</html>
"""

    @classmethod
    def get_server_header(cls, custom: Optional[str] = None) -> str:
        """Get HTTP Server header."""
        return custom or random.choice(cls.SERVER_HEADERS)

    @classmethod
    def get_error_page(
        cls,
        status: int,
        path: str = "/",
        host: str = "localhost",
        port: int = 80,
        server: Optional[str] = None,
    ) -> str:
        """Get HTTP error page."""
        server = server or cls.get_server_header()
        templates = {
            403: cls.ERROR_403,
            404: cls.ERROR_404,
            500: cls.ERROR_500,
        }
        template = templates.get(status, cls.ERROR_404)
        return template.format(path=path, host=host, port=port, server=server)

    @classmethod
    def get_login_page(cls, error: str = "", wordpress: bool = False) -> str:
        """Get login page HTML."""
        error_html = f'<div class="error">{error}</div>' if error else ""
        template = cls.WORDPRESS_LOGIN if wordpress else cls.LOGIN_PAGE
        return template.format(error=error_html)


class FTPTemplates:
    """FTP server response templates."""

    BANNERS = [
        "220 (vsFTPd 3.0.5)",
        "220 ProFTPD Server (ProFTPD) [ubuntu-server]",
        "220 FTP Server ready",
        "220 Pure-FTPd [privsep] [TLS]",
    ]

    RESPONSES = {
        "welcome": "220 {banner}",
        "user_ok": "331 Please specify the password.",
        "login_ok": "230 Login successful.",
        "login_fail": "530 Login incorrect.",
        "pwd": '257 "{path}" is the current directory',
        "cwd_ok": "250 Directory successfully changed.",
        "cwd_fail": "550 Failed to change directory.",
        "type": "200 Switching to {mode} mode.",
        "pasv": "227 Entering Passive Mode ({addr}).",
        "port": "200 PORT command successful.",
        "list_start": "150 Here comes the directory listing.",
        "list_end": "226 Directory send OK.",
        "retr_start": "150 Opening BINARY mode data connection for {file} ({size} bytes).",
        "retr_end": "226 Transfer complete.",
        "stor_start": "150 Ok to send data.",
        "stor_end": "226 Transfer complete.",
        "quit": "221 Goodbye.",
        "unknown": "500 Unknown command.",
        "not_logged_in": "530 Please login with USER and PASS.",
        "file_not_found": "550 {file}: No such file or directory",
        "permission_denied": "550 Permission denied.",
        "syst": "215 UNIX Type: L8",
        "feat": "211-Features:\n EPRT\n EPSV\n MDTM\n PASV\n REST STREAM\n SIZE\n TVFS\n UTF8\n211 End",
        "noop": "200 NOOP ok.",
    }

    @classmethod
    def get_banner(cls, custom: Optional[str] = None) -> str:
        """Get FTP banner."""
        banner = custom or random.choice(cls.BANNERS)
        return cls.RESPONSES["welcome"].format(banner=banner)

    @classmethod
    def get_response(cls, code: str, **kwargs) -> str:
        """Get FTP response by code."""
        template = cls.RESPONSES.get(code, cls.RESPONSES["unknown"])
        return template.format(**kwargs)

    @classmethod
    def format_list_entry(
        cls,
        name: str,
        is_dir: bool = False,
        size: int = 0,
        owner: str = "root",
        group: str = "root",
        perms: str = "rw-r--r--",
    ) -> str:
        """Format a single LIST entry."""
        type_char = "d" if is_dir else "-"
        return f"{type_char}{perms}    1 {owner:8} {group:8} {size:8} Nov 20 10:00 {name}"
