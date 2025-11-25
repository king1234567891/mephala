"""
Fake Filesystem Module

In-memory virtual filesystem for SSH and FTP honeypots.
Simulates a realistic Linux directory structure with fake files.
"""

from __future__ import annotations

import os
import random
import string
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional


class FileType(Enum):
    FILE = "file"
    DIRECTORY = "directory"
    SYMLINK = "symlink"


@dataclass
class FileNode:
    """Represents a file or directory in the virtual filesystem."""

    name: str
    file_type: FileType
    permissions: str = "rw-r--r--"
    owner: str = "root"
    group: str = "root"
    size: int = 0
    mtime: datetime = field(default_factory=datetime.now)
    content: bytes = b""
    link_target: Optional[str] = None
    children: dict[str, "FileNode"] = field(default_factory=dict)

    def is_dir(self) -> bool:
        return self.file_type == FileType.DIRECTORY

    def is_file(self) -> bool:
        return self.file_type == FileType.FILE

    def is_symlink(self) -> bool:
        return self.file_type == FileType.SYMLINK


class FakeFilesystem:
    """
    Virtual filesystem that mimics a Linux system.
    
    Provides realistic directory structure and file contents
    for honeypot services to use.
    """

    def __init__(self, hostname: str = "ubuntu-server"):
        self._hostname = hostname
        self._root = self._create_root()
        self._cwd = "/"
        self._build_filesystem()

    def _create_root(self) -> FileNode:
        """Create the root directory."""
        return FileNode(
            name="/",
            file_type=FileType.DIRECTORY,
            permissions="rwxr-xr-x",
            children={},
        )

    def _build_filesystem(self) -> None:
        """Build a realistic Linux filesystem structure."""
        # Create standard directories
        dirs = [
            "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64",
            "/media", "/mnt", "/opt", "/proc", "/root", "/run", "/sbin",
            "/srv", "/sys", "/tmp", "/usr", "/var",
            "/usr/bin", "/usr/lib", "/usr/local", "/usr/share",
            "/var/log", "/var/www", "/var/tmp",
            "/home/admin", "/home/user",
        ]

        for dir_path in dirs:
            self._mkdir(dir_path)

        # Add fake files
        self._add_etc_files()
        self._add_var_files()
        self._add_home_files()
        self._add_bin_files()

    def _mkdir(self, path: str) -> None:
        """Create a directory at the given path."""
        parts = [p for p in path.split("/") if p]
        current = self._root

        for part in parts:
            if part not in current.children:
                current.children[part] = FileNode(
                    name=part,
                    file_type=FileType.DIRECTORY,
                    permissions="rwxr-xr-x",
                    mtime=self._random_past_date(),
                )
            current = current.children[part]

    def _add_file(
        self,
        path: str,
        content: str | bytes,
        permissions: str = "rw-r--r--",
        owner: str = "root",
        group: str = "root",
    ) -> None:
        """Add a file with content at the given path."""
        if isinstance(content, str):
            content = content.encode()

        dir_path = os.path.dirname(path)
        filename = os.path.basename(path)

        if dir_path:
            self._mkdir(dir_path)

        parent = self._get_node(dir_path or "/")
        if parent and parent.is_dir():
            parent.children[filename] = FileNode(
                name=filename,
                file_type=FileType.FILE,
                permissions=permissions,
                owner=owner,
                group=group,
                size=len(content),
                content=content,
                mtime=self._random_past_date(),
            )

    def _random_past_date(self) -> datetime:
        """Generate a random date in the past year."""
        days_ago = random.randint(1, 365)
        return datetime.now() - timedelta(days=days_ago)

    def _add_etc_files(self) -> None:
        """Add common /etc files."""
        # /etc/passwd
        passwd_content = f"""root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System:/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:102:105::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:103:106:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
syslog:x:104:111::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
admin:x:1000:1000:Admin User,,,:/home/admin:/bin/bash
user:x:1001:1001:Regular User,,,:/home/user:/bin/bash
"""
        self._add_file("/etc/passwd", passwd_content)

        # /etc/shadow (fake hashes)
        shadow_content = """root:$6$rounds=4096$fakesalt$fakehashedpasswordnotreal:19500:0:99999:7:::
daemon:*:19500:0:99999:7:::
bin:*:19500:0:99999:7:::
sys:*:19500:0:99999:7:::
admin:$6$rounds=4096$anothersalt$anotherfakehashedpassword:19500:0:99999:7:::
user:$6$rounds=4096$usersalt$userfakehashedpassword:19500:0:99999:7:::
"""
        self._add_file("/etc/shadow", shadow_content, permissions="r--------")

        # /etc/hostname
        self._add_file("/etc/hostname", f"{self._hostname}\n")

        # /etc/hosts
        hosts_content = f"""127.0.0.1	localhost
127.0.1.1	{self._hostname}

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
"""
        self._add_file("/etc/hosts", hosts_content)

        # /etc/os-release
        os_release = """PRETTY_NAME="Ubuntu 22.04.3 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=jammy
"""
        self._add_file("/etc/os-release", os_release)

        # /etc/ssh/sshd_config
        sshd_config = """# OpenSSH Server Configuration
Port 22
AddressFamily any
ListenAddress 0.0.0.0
ListenAddress ::

HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

SyslogFacility AUTH
LogLevel INFO

LoginGraceTime 2m
PermitRootLogin prohibit-password
StrictModes yes
MaxAuthTries 6
MaxSessions 10

PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

PasswordAuthentication yes
PermitEmptyPasswords no

ChallengeResponseAuthentication no
UsePAM yes

X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*

Subsystem sftp /usr/lib/openssh/sftp-server
"""
        self._add_file("/etc/ssh/sshd_config", sshd_config)

    def _add_var_files(self) -> None:
        """Add common /var files."""
        # /var/log/auth.log
        auth_log = """Nov 20 10:15:23 ubuntu-server sshd[1234]: Accepted password for admin from 192.168.1.100 port 54321 ssh2
Nov 20 10:15:23 ubuntu-server sshd[1234]: pam_unix(sshd:session): session opened for user admin
Nov 20 10:20:45 ubuntu-server sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/ls
Nov 20 11:30:12 ubuntu-server sshd[1234]: Received disconnect from 192.168.1.100 port 54321:11: disconnected by user
"""
        self._add_file("/var/log/auth.log", auth_log)

        # /var/log/syslog
        syslog = """Nov 20 00:00:01 ubuntu-server CRON[9876]: (root) CMD (test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily ))
Nov 20 06:25:01 ubuntu-server CRON[9877]: (root) CMD (test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly ))
Nov 20 10:15:22 ubuntu-server systemd[1]: Started Session 42 of user admin.
Nov 20 10:15:23 ubuntu-server systemd-logind[456]: New session 42 of user admin.
"""
        self._add_file("/var/log/syslog", syslog)

    def _add_home_files(self) -> None:
        """Add user home directory files."""
        # Admin user files
        self._mkdir("/home/admin/.ssh")
        self._add_file(
            "/home/admin/.ssh/authorized_keys",
            "ssh-rsa AAAAB3NzaC1... admin@workstation\n",
            owner="admin",
            group="admin",
        )
        self._add_file(
            "/home/admin/.bashrc",
            self._get_bashrc_content(),
            owner="admin",
            group="admin",
        )
        self._add_file(
            "/home/admin/.bash_history",
            self._get_bash_history(),
            owner="admin",
            group="admin",
        )

        # Root files
        self._mkdir("/root/.ssh")
        self._add_file("/root/.bashrc", self._get_bashrc_content())

    def _add_bin_files(self) -> None:
        """Add fake binaries to /bin and /usr/bin."""
        binaries = [
            "ls", "cat", "pwd", "cd", "echo", "whoami", "id", "uname",
            "ps", "top", "kill", "grep", "find", "chmod", "chown",
            "mkdir", "rm", "cp", "mv", "touch", "head", "tail",
            "wget", "curl", "ssh", "scp", "tar", "gzip", "gunzip",
        ]
        for binary in binaries:
            self._add_file(
                f"/bin/{binary}",
                f"#!/bin/bash\n# {binary} binary\n",
                permissions="rwxr-xr-x",
            )

    def _get_bashrc_content(self) -> str:
        return """# ~/.bashrc: executed by bash(1) for non-login shells.

# If not running interactively, don't do anything
case $- in
    *i*) ;;
      *) return;;
esac

# don't put duplicate lines or lines starting with space in the history
HISTCONTROL=ignoreboth
HISTSIZE=1000
HISTFILESIZE=2000

# check the window size after each command
shopt -s checkwinsize

# make less more friendly for non-text input files
[ -x /usr/bin/lesspipe ] && eval "$(SHELL=/bin/sh lesspipe)"

# set a fancy prompt
PS1='\\u@\\h:\\w\\$ '

# enable color support
if [ -x /usr/bin/dircolors ]; then
    alias ls='ls --color=auto'
    alias grep='grep --color=auto'
fi

# some more ls aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
"""

    def _get_bash_history(self) -> str:
        return """ls -la
cd /var/log
cat auth.log
sudo systemctl status ssh
ps aux | grep ssh
netstat -tlnp
cat /etc/passwd
whoami
exit
"""

    def _get_node(self, path: str) -> Optional[FileNode]:
        """Get the node at the given path."""
        if path == "/":
            return self._root

        parts = [p for p in path.split("/") if p]
        current = self._root

        for part in parts:
            if part == "..":
                continue
            if part not in current.children:
                return None
            current = current.children[part]

        return current

    def exists(self, path: str) -> bool:
        """Check if a path exists."""
        return self._get_node(self._resolve_path(path)) is not None

    def is_dir(self, path: str) -> bool:
        """Check if path is a directory."""
        node = self._get_node(self._resolve_path(path))
        return node is not None and node.is_dir()

    def is_file(self, path: str) -> bool:
        """Check if path is a file."""
        node = self._get_node(self._resolve_path(path))
        return node is not None and node.is_file()

    def _resolve_path(self, path: str) -> str:
        """Resolve a path to an absolute path."""
        if not path.startswith("/"):
            path = os.path.join(self._cwd, path)
        return os.path.normpath(path)

    def listdir(self, path: str = ".") -> list[str]:
        """List directory contents."""
        node = self._get_node(self._resolve_path(path))
        if node and node.is_dir():
            return list(node.children.keys())
        return []

    def read_file(self, path: str) -> bytes:
        """Read file contents."""
        node = self._get_node(self._resolve_path(path))
        if node and node.is_file():
            return node.content
        raise FileNotFoundError(f"No such file: {path}")

    def write_file(self, path: str, content: bytes) -> None:
        """Write content to a file (for capturing uploads)."""
        self._add_file(self._resolve_path(path), content)

    def chdir(self, path: str) -> bool:
        """Change current directory."""
        resolved = self._resolve_path(path)
        if self.is_dir(resolved):
            self._cwd = resolved
            return True
        return False

    def getcwd(self) -> str:
        """Get current working directory."""
        return self._cwd

    def stat(self, path: str) -> Optional[FileNode]:
        """Get file/directory information."""
        return self._get_node(self._resolve_path(path))

    def format_ls_entry(self, node: FileNode, show_hidden: bool = False) -> str:
        """Format a single ls -l entry."""
        if node.name.startswith(".") and not show_hidden:
            return ""

        type_char = "d" if node.is_dir() else ("-" if node.is_file() else "l")
        perms = type_char + node.permissions
        links = "2" if node.is_dir() else "1"
        size = str(node.size).rjust(8)
        date = node.mtime.strftime("%b %d %H:%M")

        return f"{perms} {links} {node.owner:8} {node.group:8} {size} {date} {node.name}"

    def ls(self, path: str = ".", long_format: bool = False, show_all: bool = False) -> str:
        """Generate ls command output."""
        node = self._get_node(self._resolve_path(path))
        if not node:
            return f"ls: cannot access '{path}': No such file or directory"

        if node.is_file():
            if long_format:
                return self.format_ls_entry(node, show_all)
            return node.name

        entries = []
        if show_all:
            entries.extend([".", ".."])

        for name, child in sorted(node.children.items()):
            if not show_all and name.startswith("."):
                continue
            if long_format:
                line = self.format_ls_entry(child, show_all)
                if line:
                    entries.append(line)
            else:
                entries.append(name)

        if long_format:
            return "\n".join(entries)
        return "  ".join(entries)
