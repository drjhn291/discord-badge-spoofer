#!/usr/bin/env python3
"""
Discord Badge Spoofer
Modular client for dispatching activity telemetry to /api/v9/science.
"""

from __future__ import annotations

import base64
import ctypes
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Iterator, Sequence


BASE_DIR = Path(__file__).resolve().parent
LEGACY_GAMES_PATH = BASE_DIR.parent / "data" / "games.json"
CACHE_GAMES_PATH = BASE_DIR / "games_cache.json"
CONFIG_PATH = BASE_DIR / "client_state.json"


@dataclass(frozen=True)
class Endpoints:
    ME: str = "https://discord.com/api/v9/users/@me?with_analytics_token=true"
    SCIENCE: str = "https://discord.com/api/v9/science"
    SUPER_PROPS: str = "https://cordapi.dolfi.es/api/v2/properties/windows"
    DETECTABLES: str = "https://cdn.discordapp.com/detectables/games.json"


@dataclass(frozen=True)
class ClientSignature:
    VERSION: str = "1.0.9253"
    BUILD_NUMBER: int = 594031
    NATIVE_BUILD: int = 88414
    OS_VERSION: str = "10.0.26200"
    USER_AGENT: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) discord/1.0.9253 Chrome/148.0.7778.280 "
        "Electron/42.7.1 Safari/537.36"
    )
    BATCH_LIMIT: int = 50
    BATCH_INTERVAL_SEC: float = 1.0
    TOKEN_TTL_SEC: int = 12 * 3600


class HttpClient:
    """Minimalist urllib wrapper for JSON and plain-text requests."""

    def __init__(self, default_headers: dict[str, str] | None = None) -> None:
        self.default_headers = default_headers or {}

    def get_text(self, url: str, headers: dict[str, str] | None = None, timeout: int = 20) -> str:
        merged = {**self.default_headers, **(headers or {})}
        req = urllib.request.Request(url, headers=merged, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8")

    def get_json(self, url: str, headers: dict[str, str] | None = None, timeout: int = 15) -> dict:
        return json.loads(self.get_text(url, headers=headers, timeout=timeout))

    def post_json(
        self,
        url: str,
        payload: dict,
        headers: dict[str, str] | None = None,
        timeout: int = 15,
    ) -> tuple[int, str]:
        merged = {
            "content-type": "application/json",
            **self.default_headers,
            **(headers or {}),
        }
        raw_body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=raw_body, headers=merged, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            return exc.code, ""
        except Exception:
            return 0, ""


@dataclass
class AccountConfig:
    token: str = ""
    cookie: str = ""
    fingerprint: str = ""
    analytics_token: str = ""
    analytics_timestamp: int = 0
    claimed_ids: list[str] = field(default_factory=list)
    stats_games: int = 0
    stats_hours: float = 0.0

    @property
    def is_analytics_expired(self) -> bool:
        if not self.analytics_token:
            return True
        return (time.time() - self.analytics_timestamp) > ClientSignature.TOKEN_TTL_SEC

    @property
    def is_configured(self) -> bool:
        return bool(self.token.strip() and self.cookie.strip())


class ConfigStorage:
    """Handles reading and writing client configuration on disk."""

    def __init__(self, path: Path = CONFIG_PATH) -> None:
        self.path = path

    def load(self) -> AccountConfig:
        if not self.path.exists():
            return AccountConfig()
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            valid_keys = AccountConfig.__dataclass_fields__.keys()
            filtered = {k: raw[k] for k in valid_keys if k in raw}
            return AccountConfig(**filtered)
        except (json.JSONDecodeError, OSError, TypeError):
            return AccountConfig()

    def save(self, config: AccountConfig) -> None:
        self.path.write_text(json.dumps(asdict(config), indent=2), encoding="utf-8")


class FingerprintService:
    """Generates the executable_fingerprint field matching the desktop client."""

    _PS_TEMPLATE = r'''
param(
  [int]$TargetPid = 0,
  [string]$ExePath,
  [Parameter(Mandatory = $true)][string]$AccountId
)

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class PeCertHasher {
  const uint ASN_ENCODING = 0x00010001;
  const uint SHA256_ALG = 0x0000800C;

  [StructLayout(LayoutKind.Sequential)] struct DataBlob { public uint cbData; public IntPtr pbData; }
  [StructLayout(LayoutKind.Sequential)] struct AlgId { public IntPtr pszObjId; public DataBlob Parameters; }
  [StructLayout(LayoutKind.Sequential)] struct BitBlob { public uint cbData; public IntPtr pbData; public uint cUnusedBits; }
  [StructLayout(LayoutKind.Sequential)] struct PubKeyInfo { public AlgId Algorithm; public BitBlob PublicKey; }
  [StructLayout(LayoutKind.Sequential)] struct FileTime { public uint Low; public uint High; }
  [StructLayout(LayoutKind.Sequential)]
  struct CertInfo {
    public uint Version; public DataBlob SerialNumber; public AlgId SignatureAlgorithm; public DataBlob Issuer;
    public FileTime NotBefore; public FileTime NotAfter; public DataBlob Subject;
    public PubKeyInfo SubjectPublicKeyInfo; public BitBlob IssuerUniqueId; public BitBlob SubjectUniqueId;
    public uint ExtensionCount; public IntPtr Extensions;
  }
  [StructLayout(LayoutKind.Sequential)]
  struct CertContext {
    public uint EncodingType; public IntPtr Encoded; public uint EncodedSize;
    public IntPtr CertInfo; public IntPtr Store;
  }

  [DllImport("crypt32.dll", SetLastError = true)]
  static extern bool CryptHashPublicKeyInfo(
    IntPtr provider, uint algid, uint flags, uint encoding, ref PubKeyInfo info, byte[] hash, ref uint hashSize);

  public static byte[] Compute(IntPtr certCtx) {
    var ctx = Marshal.PtrToStructure<CertContext>(certCtx);
    var info = Marshal.PtrToStructure<CertInfo>(ctx.CertInfo);
    var digest = new byte[32];
    uint size = 32;
    if (!CryptHashPublicKeyInfo(IntPtr.Zero, SHA256_ALG, 0, ASN_ENCODING, ref info.SubjectPublicKeyInfo, digest, ref size) || size != 32)
      throw new InvalidOperationException("Failed to compute public key hash.");
    return digest;
  }
}
"@

if (-not $ExePath) {
  if ($TargetPid -le 0) { throw "Specify either -ExePath or -TargetPid." }
  $ExePath = (Get-Process -Id $TargetPid).Path
}
if (-not $ExePath) { throw "Could not resolve executable path." }

$stream = [IO.File]::Open($ExePath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
try {
  $fileLen = [UInt64]$stream.Length
  $cap = [int][Math]::Min($stream.Length, 0x10000)
  $buffer = [byte[]]::new($cap)
  $bytesRead = $stream.Read($buffer, 0, $cap)
  if ($bytesRead -lt 0x40) { throw "File header is too small." }
  if ($bytesRead -ne $cap) { [Array]::Resize([ref]$buffer, $bytesRead) }
} finally {
  $stream.Dispose()
}

if ([BitConverter]::ToUInt16($buffer, 0) -ne 0x5A4D) { throw "Not a valid MZ executable." }
$peOffset = [BitConverter]::ToInt32($buffer, 0x3C)
if ($peOffset -lt 0 -or [BitConverter]::ToUInt32($buffer, $peOffset) -ne 0x4550) { throw "Invalid PE header." }

$coff = $peOffset + 4
$numSections = [BitConverter]::ToUInt16($buffer, $coff + 2)
$timeStamp = [BitConverter]::ToUInt32($buffer, $coff + 4)
$optHeaderSize = [BitConverter]::ToUInt16($buffer, $coff + 16)
$optOffset = $coff + 20

if ([BitConverter]::ToUInt16($buffer, $optOffset) -ne 0x20B) { throw "Only PE32+ (64-bit) binaries are supported." }
$imageSize = [BitConverter]::ToUInt32($buffer, $optOffset + 56)

$secTable = $optOffset + $optHeaderSize
$sha = [Security.Cryptography.SHA256]::Create()
$hdrHash = $sha.ComputeHash([byte[]]$buffer[0..($secTable - 1)])
$secHash = $sha.ComputeHash([byte[]]$buffer[$secTable..($secTable + $numSections * 40 - 1)])

$machineId = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography" -Name MachineGuid).MachineGuid
$machineAccountHash = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($machineId + $AccountId))

$authenticode = Get-AuthenticodeSignature -LiteralPath $ExePath
$isSigned = ($authenticode.Status -eq "Valid") -and ($null -ne $authenticode.SignerCertificate)
if ($isSigned) {
  $signerName = $authenticode.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
  $certDigest = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($signerName) + [PeCertHasher]::Compute($authenticode.SignerCertificate.Handle))
} else {
  $certDigest = [byte[]]::new(32)
}

$flags = 2
if ($isSigned) { $flags += 1 }

$payload = [byte[]](@(1, [byte]$flags) +
  [BitConverter]::GetBytes($fileLen) +
  [BitConverter]::GetBytes($timeStamp) +
  [BitConverter]::GetBytes($imageSize) +
  $hdrHash + $machineAccountHash + $secHash + $certDigest)

$xorKey = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($AccountId + "https://discord.com/careers"))
for ($idx = 1; $idx -lt $payload.Length; $idx++) {
  $payload[$idx] = $payload[$idx] -bxor $xorKey[($idx - 1) -band 31]
}

[Convert]::ToBase64String($payload)
'''

    @staticmethod
    def decode_user_id(token: str) -> str:
        try:
            prefix = token.split(".", 1)[0]
            padding = "=" * (-len(prefix) % 4)
            return base64.b64decode(prefix + padding).decode("utf-8")
        except Exception:
            return ""

    @classmethod
    def build(cls, user_id: str, exe_path: str = "", pid: int = 0) -> str:
        if os.name != "nt":
            raise RuntimeError("Fingerprint generation is only supported on Windows.")

        temp_ps1 = Path(tempfile.gettempdir()) / f"fp_calc_{uuid.uuid4().hex}.ps1"
        temp_ps1.write_text(cls._PS_TEMPLATE, encoding="utf-8")
        try:
            cmd = [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(temp_ps1),
                "-AccountId",
                user_id,
            ]
            cmd.extend(["-TargetPid", str(pid)] if pid > 0 else ["-ExePath", exe_path])
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        finally:
            temp_ps1.unlink(missing_ok=True)

        if proc.returncode != 0:
            err_lines = (proc.stderr or proc.stdout or "").strip().splitlines()
            raise RuntimeError(err_lines[-1] if err_lines else "PowerShell execution failed.")

        lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        if not lines:
            raise RuntimeError("PowerShell produced no output.")
        return lines[-1]


@dataclass(frozen=True)
class GameEntry:
    id: str
    title: str
    executable: str


class GameRepository:
    """Fetches, caches, and rotates verified Windows game entries."""

    def __init__(self, http: HttpClient) -> None:
        self.http = http
        self.catalog: list[GameEntry] = []

    def _resolve_cache_file(self) -> Path:
        if LEGACY_GAMES_PATH.exists():
            return LEGACY_GAMES_PATH
        return CACHE_GAMES_PATH

    @staticmethod
    def _extract_windows_exe(executables: list[dict]) -> str | None:
        for item in executables:
            if item.get("os") == "win32" and item.get("name"):
                return item["name"]
        return None

    def _parse(self, raw_json: str) -> list[GameEntry]:
        entries = json.loads(raw_json)
        parsed: list[GameEntry] = []
        seen_ids: set[str] = set()

        for item in entries:
            gid = str(item.get("id", ""))
            if not gid.isdigit() or gid in seen_ids:
                continue
            win_exe = self._extract_windows_exe(item.get("executables", []))
            if not win_exe:
                continue
            seen_ids.add(gid)
            parsed.append(GameEntry(gid, item.get("name", "Unknown"), win_exe))
        return parsed

    def load(self) -> list[GameEntry]:
        cache_path = self._resolve_cache_file()
        if cache_path.exists():
            try:
                content = cache_path.read_text(encoding="utf-8").strip()
                if content:
                    games = self._parse(content)
                    if games:
                        self.catalog = games
                        return self.catalog
            except (json.JSONDecodeError, OSError):
                pass

        try:
            downloaded = self.http.get_text(Endpoints.DETECTABLES, timeout=30)
            try:
                cache_path.parent.mkdir(parents=True, exist_ok=True)
                cache_path.write_text(downloaded, encoding="utf-8")
            except OSError:
                pass
            self.catalog = self._parse(downloaded)
        except Exception:
            self.catalog = []

        return self.catalog

    def pick_next_batch(self, amount: int, config: AccountConfig) -> list[GameEntry]:
        """Prioritizes unclaimed games and rotates previously used ones when needed."""
        by_id = {g.id: g for g in self.catalog}
        used_set = set(config.claimed_ids)

        fresh_ids = [g.id for g in self.catalog if g.id not in used_set]
        recycled_ids = [gid for gid in config.claimed_ids if gid in by_id]

        if len(fresh_ids) >= amount:
            chosen_ids = fresh_ids[:amount]
        else:
            chosen_ids = list(fresh_ids)
            needed = amount - len(chosen_ids)
            if recycled_ids and needed > 0:
                rotated = recycled_ids[needed:] + recycled_ids[:needed]
                chosen_ids.extend(rotated[:needed])

        config.claimed_ids = [gid for gid in config.claimed_ids if gid not in chosen_ids] + chosen_ids
        return [by_id[gid] for gid in chosen_ids if gid in by_id]


@dataclass
class TelemetrySession:
    heartbeat_session_id: str
    launch_signature: str
    super_properties_b64: str
    sequence_counter: int = 0

    def next_seq(self) -> int:
        self.sequence_counter += 1
        return self.sequence_counter


class DiscordTelemetryClient:
    """Builds game sessions and dispatches event batches to Discord."""

    def __init__(self, config: AccountConfig, storage: ConfigStorage, http: HttpClient) -> None:
        self.config = config
        self.storage = storage
        self.http = http
        self.session = self._create_session()

    def _fallback_properties(self) -> dict:
        return {
            "os": "Windows",
            "browser": "Discord Client",
            "release_channel": "stable",
            "client_version": ClientSignature.VERSION,
            "os_version": ClientSignature.OS_VERSION,
            "os_arch": "x64",
            "app_arch": "x64",
            "system_locale": "en-GB",
            "has_client_mods": False,
            "browser_user_agent": ClientSignature.USER_AGENT,
            "browser_version": "42.7.1",
            "os_sdk_version": "26200",
            "client_build_number": ClientSignature.BUILD_NUMBER,
            "native_build_number": ClientSignature.NATIVE_BUILD,
            "client_event_source": None,
            "client_app_state": "focused",
        }

    def _create_session(self) -> TelemetrySession:
        hb_id = str(uuid.uuid4())
        launch_sig = str(uuid.uuid4())

        status, raw = self.http.post_json(Endpoints.SUPER_PROPS, {}, timeout=10)
        if status == 200 and raw:
            try:
                props = json.loads(raw)["properties"]
            except (KeyError, json.JSONDecodeError):
                props = self._fallback_properties()
        else:
            props = self._fallback_properties()

        props["client_launch_id"] = str(uuid.uuid4())
        props["launch_signature"] = launch_sig
        props["client_heartbeat_session_id"] = hb_id

        encoded = base64.b64encode(
            json.dumps(props, separators=(",", ":")).encode("utf-8")
        ).decode("ascii")

        return TelemetrySession(
            heartbeat_session_id=hb_id,
            launch_signature=launch_sig,
            super_properties_b64=encoded,
        )

    def rotate_session(self) -> None:
        self.session = self._create_session()

    def sync_analytics_token(self, force: bool = False) -> None:
        if not force and not self.config.is_analytics_expired:
            return

        headers = {
            "authorization": self.config.token,
            "x-super-properties": self.session.super_properties_b64,
        }
        try:
            data = self.http.get_json(Endpoints.ME, headers=headers)
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"Token rejected by Discord (HTTP {exc.code}).") from exc

        token = data.get("analytics_token")
        if not token:
            raise RuntimeError("Response did not include an analytics_token.")

        self.config.analytics_token = token
        self.config.analytics_timestamp = int(time.time())
        self.storage.save(self.config)

    def _build_launch_event(self, game: GameEntry, timestamp_ms: int) -> dict:
        props = {
            "client_track_timestamp": timestamp_ms,
            "client_heartbeat_session_id": self.session.heartbeat_session_id,
            "event_sequence_number": self.session.next_seq(),
            "game": game.title,
            "game_id": game.id,
            "verified": True,
            "elevated": False,
            "is_launcher": False,
            "game_platform": "desktop",
            "detection_method": "verified_game",
            "is_overlay_enabled": False,
            "is_overlay_game_enabled": True,
            "is_overlay_game_source": "OOP_DEFAULT_DATABASE",
            "fullscreen_type": "UNKNOWN",
            "hardware_display_count": 1,
            "overlay_method": "Disabled",
            "activity_status_enabled": True,
            "activity_status_shared_guilds": [],
            "current_user_status": "online",
            "game_detection_enabled": True,
            "executable_path": game.executable,
            "voice_channel_id": None,
            "voice_channel_type": None,
            "voice_channel_bitrate": None,
            "voice_channel_guild_id": None,
            "hidden_by_distributor": False,
            "game_metadata": None,
            "client_performance_cpu": None,
            "client_performance_memory": None,
            "cpu_core_count": None,
            "accessibility_features": 0,
            "rendered_locale": "en-GB",
            "launch_signature": self.session.launch_signature,
            "client_rtc_state": None,
            "client_app_state": "focused",
            "client_send_timestamp": timestamp_ms,
        }
        if self.config.fingerprint:
            props["executable_fingerprint"] = self.config.fingerprint

        return {"type": "launch_game", "properties": props}

    def _build_heartbeat_event(
        self,
        game: GameEntry,
        game_session_id: str,
        duration_ms: int,
        is_initial: bool,
        is_final: bool,
        timestamp_ms: int,
    ) -> dict:
        return {
            "type": "running_game_heartbeat",
            "properties": {
                "client_track_timestamp": timestamp_ms,
                "client_heartbeat_session_id": self.session.heartbeat_session_id,
                "event_sequence_number": self.session.next_seq(),
                "game_id": game.id,
                "game_name": game.title,
                "game_metadata": None,
                "game_executable": game.executable,
                "game_detection_enabled": True,
                "initial_heartbeat": is_initial,
                "final_heartbeat": is_final,
                "game_session_id": game_session_id,
                "duration_tracked_ms": duration_ms,
                "rtc_connection_id": None,
                "media_session_id": None,
                "launch_signature": self.session.launch_signature,
                "client_app_state": "focused",
                "client_send_timestamp": timestamp_ms,
            },
        }

    def generate_game_sequence(self, game: GameEntry, duration_ms: int) -> list[dict]:
        game_sid = str(uuid.uuid4())
        end_ts = int(time.time() * 1000)
        start_ts = max(end_ts - duration_ms, 0) if (end_ts - duration_ms) >= 0 else end_ts

        return [
            self._build_heartbeat_event(game, game_sid, 0, True, False, start_ts),
            self._build_launch_event(game, end_ts),
            self._build_heartbeat_event(game, game_sid, duration_ms, False, True, end_ts),
        ]

    def send_events(self, events: Sequence[dict]) -> int:
        headers = {
            "accept": "*/*",
            "accept-language": "en-GB",
            "authorization": self.config.token,
            "cookie": self.config.cookie,
            "origin": "https://discord.com",
            "referer": "https://discord.com/channels/@me",
            "x-debug-options": "bugReporterEnabled",
            "x-discord-locale": "en-GB",
            "x-discord-timezone": "Europe/Oslo",
            "x-super-properties": self.session.super_properties_b64,
        }
        payload = {"token": self.config.analytics_token, "events": list(events)}
        status, _ = self.http.post_json(Endpoints.SCIENCE, payload, headers=headers)
        return status


class TerminalUI:
    CYAN = "\x1b[96m"
    GREEN = "\x1b[92m"
    YELLOW = "\x1b[93m"
    RED = "\x1b[91m"
    DIM = "\x1b[90m"
    BOLD = "\x1b[1m"
    RESET = "\x1b[0m"

    def __init__(self) -> None:
        for stream in (sys.stdout, sys.stderr):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass
        if sys.platform == "win32":
            self._enable_windows_vt()

    @staticmethod
    def _enable_windows_vt() -> None:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)

    def clear(self) -> None:
        print("\x1b[2J\x1b[3J\x1b[H", end="")

    def header(self) -> None:
        self.clear()
        print(f"\n  {self.BOLD}{self.CYAN}DISCORD BADGE SPOOFER{self.RESET}")
        print(f"  {self.DIM}{'─' * 46}{self.RESET}\n")

    def log(self, tag: str, message: str, color: str = "") -> None:
        clock = time.strftime("%H:%M:%S")
        c = color or self.RESET
        print(f"  {self.DIM}[{clock}]{self.RESET} {c}{tag:<12}{self.RESET} {message}")

    def success(self, tag: str, msg: str) -> None:
        self.log(tag, msg, self.GREEN)

    def warn(self, tag: str, msg: str) -> None:
        self.log(tag, msg, self.YELLOW)

    def error(self, tag: str, msg: str) -> None:
        self.log(tag, msg, self.RED)

    def divider(self) -> None:
        print(f"  {self.DIM}{'─' * 46}{self.RESET}")


def _chunk_iterable(items: Sequence[GameEntry], size: int) -> Iterator[Sequence[GameEntry]]:
    for idx in range(0, len(items), size):
        yield items[idx : idx + size]


class SpooferCLI:
    def __init__(self) -> None:
        self.ui = TerminalUI()
        self.storage = ConfigStorage()
        self.config = self.storage.load()
        self.http = HttpClient(default_headers={"user-agent": ClientSignature.USER_AGENT})
        self.catalog = GameRepository(self.http)
        self.telemetry: DiscordTelemetryClient | None = None

    def run(self) -> None:
        self.ui.header()

        if not self._ensure_credentials():
            return

        self.ui.log("CATALOG", "Loading game list...")
        games = self.catalog.load()
        if not games:
            self.ui.error("CATALOG", "Failed to load the detectable games list.")
            return
        self.ui.success("CATALOG", f"{len(games)} Windows games available.")

        if not self.config.fingerprint:
            self.ui.warn("FINGERPRINT", "Not set (recommended for games-played tracking).")

        self.ui.log("SESSION", "Validating credentials and analytics_token...")
        self.telemetry = DiscordTelemetryClient(self.config, self.storage, self.http)
        try:
            self.telemetry.sync_analytics_token()
        except Exception as exc:
            self.ui.error("AUTH", str(exc))
            return

        self.ui.success("AUTH", "Session initialized.")
        time.sleep(0.7)
        self._main_menu()

    def _ensure_credentials(self) -> bool:
        if not self.config.token.strip():
            self.ui.log("SETUP", "Enter your Discord account token:")
            val = input(f"  {self.ui.CYAN}>{self.ui.RESET} ").strip()
            if not val:
                self.ui.error("SETUP", "Token is required.")
                return False
            self.config.token = val
            self.storage.save(self.config)

        if not self.config.cookie.strip():
            self.ui.log("SETUP", "Enter your cookie header (cf_clearance=...):")
            val = input(f"  {self.ui.CYAN}>{self.ui.RESET} ").strip()
            if not val:
                self.ui.error("SETUP", "Cookie is required.")
                return False
            self.config.cookie = val
            self.storage.save(self.config)

        return True

    def _main_menu(self) -> None:
        actions: dict[str, Callable[[], bool]] = {
            "1": self._action_claim_playtime,
            "2": self._action_refresh_auth,
            "3": self._action_configure_fingerprint,
            "4": lambda: False,
        }

        while True:
            self.ui.header()
            self.ui.log("GAMES", f"{len(self.catalog.catalog)} loaded")
            self.ui.log(
                "CLAIMED",
                f"{self.config.stats_games} games · {self.config.stats_hours:,.1f} hours",
            )
            self.ui.divider()
            print(f"  {self.ui.CYAN}[1]{self.ui.RESET} Claim playtime & games")
            print(f"  {self.ui.CYAN}[2]{self.ui.RESET} Update cookie / refresh session")
            print(f"  {self.ui.CYAN}[3]{self.ui.RESET} Generate executable_fingerprint (Windows)")
            print(f"  {self.ui.CYAN}[4]{self.ui.RESET} Exit")
            self.ui.divider()

            choice = input(f"  {self.ui.CYAN}Select >{self.ui.RESET} ").strip()
            print()

            handler = actions.get(choice)
            if handler is None:
                self.ui.warn("MENU", "Invalid option.")
                time.sleep(0.8)
                continue

            if not handler():
                break

    def _action_claim_playtime(self) -> bool:
        assert self.telemetry is not None
        total_available = len(self.catalog.catalog)

        raw_count = input(f"  Number of games [max {total_available}]: ").strip()
        try:
            count = int(raw_count) if raw_count else total_available
            if count <= 0:
                raise ValueError
        except ValueError:
            self.ui.error("INPUT", "Invalid game count.")
            time.sleep(1)
            return True

        count = min(count, total_available)

        raw_hours = input("  Hours per game [1.0]: ").strip()
        try:
            hours = float(raw_hours) if raw_hours else 1.0
            if hours <= 0:
                raise ValueError
        except ValueError:
            self.ui.error("INPUT", "Invalid hour amount.")
            time.sleep(1)
            return True

        try:
            self.telemetry.sync_analytics_token(force=False)
        except Exception as exc:
            self.ui.error("AUTH", str(exc))
            time.sleep(1.5)
            return True

        selected_games = self.catalog.pick_next_batch(count, self.config)
        duration_ms = int(hours * 3600 * 1000)

        self.ui.divider()
        self.ui.log(
            "DISPATCH",
            f"Processing {len(selected_games)} games ({hours:g}h each)...",
            self.ui.CYAN,
        )

        completed = 0
        for idx, batch in enumerate(_chunk_iterable(selected_games, ClientSignature.BATCH_LIMIT), 1):
            events_payload: list[dict] = []
            for game in batch:
                events_payload.extend(self.telemetry.generate_game_sequence(game, duration_ms))

            status = self.telemetry.send_events(events_payload)
            if status == 204:
                completed += len(batch)
                self.ui.success(f"BATCH {idx}", f"{completed}/{len(selected_games)} games accepted")
            elif status in (401, 403):
                self.ui.error(
                    f"BATCH {idx}",
                    f"HTTP {status}: Session or cookie rejected. Use option 2 to refresh.",
                )
                break
            else:
                self.ui.warn(f"BATCH {idx}", f"Unexpected response: HTTP {status}")

            time.sleep(ClientSignature.BATCH_INTERVAL_SEC)

        self.config.stats_games += completed
        self.config.stats_hours += completed * hours
        self.storage.save(self.config)

        print()
        self.ui.success("SUMMARY", f"{completed} games claimed ({completed * hours:,.1f}h).")
        input(f"\n  {self.ui.DIM}Press Enter to return to menu...{self.ui.RESET}")
        return True

    def _action_refresh_auth(self) -> bool:
        assert self.telemetry is not None
        ans = input("  Update cookie? [y/N]: ").strip().lower()
        if ans in ("y", "yes"):
            new_cookie = input("  New cookie: ").strip()
            if new_cookie:
                self.config.cookie = new_cookie
                self.ui.success("COOKIE", "Cookie updated.")

        self.ui.log("AUTH", "Refreshing analytics_token and session UUIDs...")
        try:
            self.telemetry.rotate_session()
            self.telemetry.sync_analytics_token(force=True)
            self.storage.save(self.config)
            self.ui.success("AUTH", "Session refreshed.")
        except Exception as exc:
            self.ui.error("AUTH", str(exc))

        time.sleep(1.2)
        return True

    def _action_configure_fingerprint(self) -> bool:
        uid = FingerprintService.decode_user_id(self.config.token)
        if not uid:
            self.ui.error("FINGERPRINT", "Could not extract user ID from token.")
            time.sleep(1.5)
            return True

        self.ui.log("FINGERPRINT", f"Detected account ID: {uid}")
        target = input("  Path to a game .exe or active PID: ").strip().strip('"')
        if not target:
            return True

        pid = int(target) if target.isdigit() else 0
        exe_path = "" if pid > 0 else target

        if exe_path and not Path(exe_path).exists():
            self.ui.error("FINGERPRINT", f"File not found: {exe_path}")
            time.sleep(1.5)
            return True

        self.ui.log("FINGERPRINT", "Computing executable fingerprint...")
        try:
            fp = FingerprintService.build(uid, exe_path=exe_path, pid=pid)
            self.config.fingerprint = fp
            self.storage.save(self.config)
            self.ui.success("FINGERPRINT", f"Saved ({len(fp)} chars).")
        except Exception as exc:
            self.ui.error("FINGERPRINT", str(exc))

        time.sleep(1.5)
        return True


def main() -> None:
    try:
        SpooferCLI().run()
    except KeyboardInterrupt:
        print("\n  Interrupted by user.")


if __name__ == "__main__":
    main()
