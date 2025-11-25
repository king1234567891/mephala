"""
Session Manager Module

Track and manage concurrent attacker sessions across all honeypot services.
Provides session lifecycle management, statistics, and correlation.
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Optional


class SessionState(Enum):
    """Session lifecycle states."""
    CONNECTING = "connecting"
    AUTHENTICATING = "authenticating"
    AUTHENTICATED = "authenticated"
    ACTIVE = "active"
    DISCONNECTING = "disconnecting"
    CLOSED = "closed"


@dataclass
class SessionStats:
    """Statistics for a single session."""
    commands_executed: int = 0
    requests_made: int = 0
    files_uploaded: int = 0
    files_downloaded: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    auth_attempts: int = 0
    successful_auth: bool = False


@dataclass
class Session:
    """Represents an active attacker session."""
    
    session_id: str
    source_ip: str
    source_port: int
    service_type: str
    started_at: datetime = field(default_factory=datetime.utcnow)
    ended_at: Optional[datetime] = None
    state: SessionState = SessionState.CONNECTING
    username: Optional[str] = None
    stats: SessionStats = field(default_factory=SessionStats)
    metadata: dict[str, Any] = field(default_factory=dict)
    
    @property
    def duration(self) -> timedelta:
        """Get session duration."""
        end = self.ended_at or datetime.utcnow()
        return end - self.started_at
    
    @property
    def duration_seconds(self) -> float:
        """Get session duration in seconds."""
        return self.duration.total_seconds()
    
    @property
    def is_active(self) -> bool:
        """Check if session is still active."""
        return self.state not in (SessionState.CLOSED, SessionState.DISCONNECTING)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert session to dictionary."""
        return {
            "session_id": self.session_id,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "service_type": self.service_type,
            "started_at": self.started_at.isoformat(),
            "ended_at": self.ended_at.isoformat() if self.ended_at else None,
            "duration_seconds": self.duration_seconds,
            "state": self.state.value,
            "username": self.username,
            "stats": {
                "commands_executed": self.stats.commands_executed,
                "requests_made": self.stats.requests_made,
                "files_uploaded": self.stats.files_uploaded,
                "files_downloaded": self.stats.files_downloaded,
                "bytes_sent": self.stats.bytes_sent,
                "bytes_received": self.stats.bytes_received,
                "auth_attempts": self.stats.auth_attempts,
                "successful_auth": self.stats.successful_auth,
            },
            "metadata": self.metadata,
        }


class SessionManager:
    """
    Manages all active sessions across honeypot services.
    
    Thread-safe session tracking with automatic cleanup of stale sessions.
    """
    
    def __init__(
        self,
        session_timeout: int = 3600,
        cleanup_interval: int = 300,
    ):
        """
        Initialize session manager.
        
        Args:
            session_timeout: Max session duration in seconds before auto-close
            cleanup_interval: Interval in seconds between cleanup runs
        """
        self._sessions: dict[str, Session] = {}
        self._lock = asyncio.Lock()
        self._session_timeout = session_timeout
        self._cleanup_interval = cleanup_interval
        self._cleanup_task: Optional[asyncio.Task] = None
        self._running = False
    
    async def start(self) -> None:
        """Start the session manager and cleanup task."""
        if self._running:
            return
        self._running = True
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
    
    async def stop(self) -> None:
        """Stop the session manager and cleanup task."""
        self._running = False
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            self._cleanup_task = None
        
        # Close all active sessions
        async with self._lock:
            for session in self._sessions.values():
                if session.is_active:
                    session.state = SessionState.CLOSED
                    session.ended_at = datetime.utcnow()
    
    async def _cleanup_loop(self) -> None:
        """Periodically clean up stale sessions."""
        while self._running:
            try:
                await asyncio.sleep(self._cleanup_interval)
                await self._cleanup_stale_sessions()
            except asyncio.CancelledError:
                break
            except Exception:
                pass
    
    async def _cleanup_stale_sessions(self) -> None:
        """Remove sessions that have exceeded the timeout."""
        now = datetime.utcnow()
        timeout = timedelta(seconds=self._session_timeout)
        
        async with self._lock:
            stale_ids = [
                sid for sid, session in self._sessions.items()
                if session.is_active and (now - session.started_at) > timeout
            ]
            
            for sid in stale_ids:
                session = self._sessions[sid]
                session.state = SessionState.CLOSED
                session.ended_at = now
    
    def generate_session_id(self) -> str:
        """Generate a unique session ID."""
        return str(uuid.uuid4())
    
    async def create_session(
        self,
        source_ip: str,
        source_port: int,
        service_type: str,
        session_id: Optional[str] = None,
    ) -> Session:
        """
        Create and register a new session.
        
        Args:
            source_ip: Client IP address
            source_port: Client port
            service_type: Type of service (ssh, http, ftp)
            session_id: Optional custom session ID
        
        Returns:
            The created Session object
        """
        session_id = session_id or self.generate_session_id()
        
        session = Session(
            session_id=session_id,
            source_ip=source_ip,
            source_port=source_port,
            service_type=service_type,
        )
        
        async with self._lock:
            self._sessions[session_id] = session
        
        return session
    
    async def get_session(self, session_id: str) -> Optional[Session]:
        """Get a session by ID."""
        async with self._lock:
            return self._sessions.get(session_id)
    
    async def update_session_state(
        self,
        session_id: str,
        state: SessionState,
    ) -> bool:
        """Update session state."""
        async with self._lock:
            session = self._sessions.get(session_id)
            if session:
                session.state = state
                if state == SessionState.CLOSED:
                    session.ended_at = datetime.utcnow()
                return True
            return False
    
    async def set_authenticated(
        self,
        session_id: str,
        username: str,
    ) -> bool:
        """Mark session as authenticated."""
        async with self._lock:
            session = self._sessions.get(session_id)
            if session:
                session.state = SessionState.AUTHENTICATED
                session.username = username
                session.stats.successful_auth = True
                return True
            return False
    
    async def record_auth_attempt(self, session_id: str) -> None:
        """Record an authentication attempt."""
        async with self._lock:
            session = self._sessions.get(session_id)
            if session:
                session.stats.auth_attempts += 1
    
    async def record_command(self, session_id: str) -> None:
        """Record a command execution."""
        async with self._lock:
            session = self._sessions.get(session_id)
            if session:
                session.stats.commands_executed += 1
    
    async def record_request(self, session_id: str) -> None:
        """Record an HTTP request."""
        async with self._lock:
            session = self._sessions.get(session_id)
            if session:
                session.stats.requests_made += 1
    
    async def record_file_upload(self, session_id: str, size: int = 0) -> None:
        """Record a file upload."""
        async with self._lock:
            session = self._sessions.get(session_id)
            if session:
                session.stats.files_uploaded += 1
                session.stats.bytes_received += size
    
    async def record_file_download(self, session_id: str, size: int = 0) -> None:
        """Record a file download."""
        async with self._lock:
            session = self._sessions.get(session_id)
            if session:
                session.stats.files_downloaded += 1
                session.stats.bytes_sent += size
    
    async def record_bytes(
        self,
        session_id: str,
        sent: int = 0,
        received: int = 0,
    ) -> None:
        """Record bytes transferred."""
        async with self._lock:
            session = self._sessions.get(session_id)
            if session:
                session.stats.bytes_sent += sent
                session.stats.bytes_received += received
    
    async def set_metadata(
        self,
        session_id: str,
        key: str,
        value: Any,
    ) -> None:
        """Set session metadata."""
        async with self._lock:
            session = self._sessions.get(session_id)
            if session:
                session.metadata[key] = value
    
    async def close_session(self, session_id: str) -> Optional[Session]:
        """
        Close a session and return its final state.
        
        Args:
            session_id: Session to close
        
        Returns:
            The closed Session object or None if not found
        """
        async with self._lock:
            session = self._sessions.get(session_id)
            if session:
                session.state = SessionState.CLOSED
                session.ended_at = datetime.utcnow()
                return session
            return None
    
    async def get_active_sessions(
        self,
        service_type: Optional[str] = None,
    ) -> list[Session]:
        """Get all active sessions, optionally filtered by service."""
        async with self._lock:
            sessions = [s for s in self._sessions.values() if s.is_active]
            if service_type:
                sessions = [s for s in sessions if s.service_type == service_type]
            return sessions
    
    async def get_sessions_by_ip(self, ip: str) -> list[Session]:
        """Get all sessions from a specific IP."""
        async with self._lock:
            return [s for s in self._sessions.values() if s.source_ip == ip]
    
    async def get_stats(self) -> dict[str, Any]:
        """Get overall session statistics."""
        async with self._lock:
            total = len(self._sessions)
            active = sum(1 for s in self._sessions.values() if s.is_active)
            by_service = {}
            by_state = {}
            
            for session in self._sessions.values():
                by_service[session.service_type] = by_service.get(session.service_type, 0) + 1
                by_state[session.state.value] = by_state.get(session.state.value, 0) + 1
            
            return {
                "total_sessions": total,
                "active_sessions": active,
                "closed_sessions": total - active,
                "by_service": by_service,
                "by_state": by_state,
            }


# Global session manager instance
_session_manager: Optional[SessionManager] = None


def get_session_manager() -> SessionManager:
    """Get the global session manager instance."""
    global _session_manager
    if _session_manager is None:
        _session_manager = SessionManager()
    return _session_manager


async def init_session_manager(
    session_timeout: int = 3600,
    cleanup_interval: int = 300,
) -> SessionManager:
    """Initialize and start the global session manager."""
    global _session_manager
    _session_manager = SessionManager(
        session_timeout=session_timeout,
        cleanup_interval=cleanup_interval,
    )
    await _session_manager.start()
    return _session_manager


async def close_session_manager() -> None:
    """Stop and cleanup the global session manager."""
    global _session_manager
    if _session_manager:
        await _session_manager.stop()
        _session_manager = None
