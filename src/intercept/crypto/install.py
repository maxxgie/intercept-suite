"""Trust store integration for the Intercept root certificate.

Browsers do not share a trust store, and each platform reads a different one.
This module works out which stores a browser on this machine actually reads,
and offers to install the root CA into them.

Every target also carries the manual instructions for its platform, so a user
without ``certutil`` or root access is never stuck.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

__all__ = ["Target", "targets", "install", "uninstall", "CERT_LABEL"]

CERT_LABEL = "Intercept"

#: Trust flags for certutil: a trusted CA for SSL, email and object signing.
NSS_TRUST = "CT,C,C"


@dataclass
class Target:
    """One place a root certificate can be installed."""

    name: str
    label: str
    available: bool
    reason: str = ""
    location: str = ""
    steps: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "label": self.label,
            "available": self.available,
            "reason": self.reason,
            "location": self.location,
            "steps": list(self.steps),
        }


# --------------------------------------------------------------------- helpers


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, check=False)


def _certutil() -> str | None:
    return shutil.which("certutil")


def _which(*names: str) -> list[str]:
    return [name for name in names if shutil.which(name)]


def _home() -> Path:
    """The home of the user, even when the command runs through sudo."""
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and sudo_user != "root":
        try:
            import pwd

            return Path(pwd.getpwnam(sudo_user).pw_dir)
        except (ImportError, KeyError):
            pass
    return Path.home()


def firefox_profiles() -> list[Path]:
    """Every Firefox profile that holds a certificate database."""
    home = _home()
    roots = [
        home / ".mozilla" / "firefox",
        home / ".var" / "app" / "org.mozilla.firefox" / ".mozilla" / "firefox",
        home / ".snap" / "firefox" / "common" / ".mozilla" / "firefox",
    ]
    found: list[Path] = []
    for root in roots:
        if not root.is_dir():
            continue
        for profile in sorted(root.iterdir()):
            if profile.is_dir() and (profile / "cert9.db").exists():
                found.append(profile)
    return found


def nss_database() -> Path:
    """The shared NSS database that Chrome, Chromium, Brave and Edge read."""
    return _home() / ".pki" / "nssdb"


#: How each distribution stores and refreshes its system trust store.
SYSTEM_STORES: dict[str, tuple[str, str, str]] = {
    # distribution: (anchors directory, refresh command, package)
    "debian": ("/usr/local/share/ca-certificates", "update-ca-certificates", "ca-certificates"),
    "suse": ("/usr/share/ca-certificates", "update-ca-certificates", "ca-certificates"),
    "fedora": (
        "/etc/pki/ca-trust/source/anchors",
        "update-ca-trust extract",
        "ca-certificates",
    ),
    "rhel": ("/etc/pki/ca-trust/source/anchors", "update-ca-trust extract", "ca-certificates"),
    "arch": (
        "/etc/ca-certificates/trust-source/anchors",
        "trust extract-compat",
        "ca-certificates",
    ),
}


def distribution() -> str:
    """The distribution family this machine belongs to."""
    if Path("/etc/debian_version").exists():
        return "debian"
    if Path("/etc/fedora-release").exists() or Path("/etc/redhat-release").exists():
        return "fedora"
    if Path("/etc/arch-release").exists():
        return "arch"
    if Path("/etc/SuSE-release").exists() or Path("/etc/os-release").exists():
        try:
            text = Path("/etc/os-release").read_text()
        except OSError:
            return "unknown"
        if "ID_LIKE" in text and "suse" in text:
            return "suse"
    return "unknown"


def package_manager() -> tuple[str, str] | None:
    """The package manager and the package that provides ``certutil``."""
    system = platform.system()
    if system == "Linux":
        if shutil.which("dnf"):
            return "dnf", "nss-tools"
        if shutil.which("apt-get"):
            return "apt-get", "libnss3-tools"
        if shutil.which("pacman"):
            return "pacman", "nss"
        if shutil.which("zypper"):
            return "zypper", "mozilla-nss-tools"
    return None


def system_store() -> tuple[Path, str] | None:
    """The anchors directory and refresh command of the system trust store."""
    family = distribution()
    entry = SYSTEM_STORES.get(family)
    if entry is None:
        return None
    directory, command, _package = entry
    return Path(directory), command


def missing_package_steps(package: str) -> list[str]:
    """How to install *package* on this machine."""
    manager = package_manager()
    if manager is None:
        return [f"install {package} with your package manager"]
    name, tool = manager
    if name == "apt-get":
        return [f"sudo apt-get install {tool}"]
    if name == "dnf":
        return [f"sudo dnf install {tool}"]
    if name == "pacman":
        return [f"sudo pacman -S {tool}"]
    if name == "zypper":
        return [f"sudo zypper install {tool}"]
    return [f"install {tool} with {name}"]


def install_dependencies() -> list[str]:
    """Install the packages needed to write to the trust stores.

    Returns one line per package that was installed.
    """
    manager = package_manager()
    if manager is None:
        return []
    name, tool = manager
    commands = {
        "dnf": ["sudo", "dnf", "install", "-y", tool],
        "apt-get": ["sudo", "apt-get", "install", "-y", tool],
        "pacman": ["sudo", "pacman", "-S", "--needed", "--noconfirm", tool],
        "zypper": ["sudo", "zypper", "install", "-y", tool],
    }
    command = commands.get(name)
    if command is None:
        return []
    print(f"running: {' '.join(command)}")
    result = subprocess.run(command, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"{' '.join(command)} failed with code {result.returncode}")
    return [f"installed {tool}"]


# ---------------------------------------------------------------- linux targets


def _linux_system() -> Target:
    store = system_store()
    if store is None:
        return Target(
            "system",
            "The system trust store",
            False,
            "the layout of the system trust store is not recognised",
            "",
            ["copy intercept-ca.crt into the directory your distribution reads"],
        )
    directory, command = store
    steps = [
        f"sudo cp {{certificate}} {directory}/intercept-ca.crt",
        f"sudo {command}",
    ]
    if not shutil.which(command.split()[0]):
        return Target(
            "system",
            "The system trust store",
            False,
            f"{command.split()[0]} is not installed",
            str(directory),
            steps,
        )
    if os.geteuid() != 0:
        return Target(
            "system",
            "The system trust store",
            False,
            "needs root: run it with sudo",
            str(directory),
            steps,
        )
    return Target(
        "system",
        "The system trust store",
        True,
        "",
        str(directory),
        steps,
    )


def _linux_nss() -> Target:
    database = nss_database()
    browsers = _which(
        "google-chrome",
        "google-chrome-stable",
        "chromium",
        "chromium-browser",
        "brave-browser",
        "microsoft-edge",
    )
    steps = missing_package_steps("certutil") + [
        f"certutil -d sql:{database} -A -n {CERT_LABEL} -t {NSS_TRUST} -i {{certificate}}",
    ]
    if not _certutil():
        return Target(
            "nss",
            "Chrome, Chromium, Brave and Edge (NSS database)",
            False,
            "certutil is missing",
            str(database),
            steps,
        )
    if not browsers:
        return Target(
            "nss",
            "Chrome, Chromium, Brave and Edge (NSS database)",
            False,
            "no NSS based browser found on this machine",
            str(database),
            steps,
        )
    return Target(
        "nss",
        "Chrome, Chromium, Brave and Edge (NSS database)",
        True,
        "",
        str(database),
        steps,
    )


def _linux_firefox() -> Target:
    profiles = firefox_profiles()
    location = str(profiles[0]) if profiles else "~/.mozilla/firefox/<profile>"
    steps = [
        "Firefox: Settings -> Privacy & Security -> Certificates -> "
        "View Certificates -> Authorities -> Import, and pick {certificate}",
        "or import it into the profile database with certutil while Firefox is closed:",
        f"certutil -d sql:{location}/cert9.db -A -n {CERT_LABEL} "
        f"-t {NSS_TRUST} -i {{certificate}}",
    ]
    if not _certutil():
        return Target(
            "firefox",
            "Firefox (profile certificate database)",
            False,
            "certutil is missing",
            location,
            steps,
        )
    if not profiles:
        return Target(
            "firefox",
            "Firefox (profile certificate database)",
            False,
            "no Firefox profile found",
            location,
            steps,
        )
    return Target(
        "firefox",
        "Firefox (profile certificate database)",
        True,
        "",
        location,
        steps,
    )


# --------------------------------------------------------------- macos targets


def _macos_keychain() -> Target:
    keychain = str(_home() / "Library" / "Keychains" / "login.keychain-db")
    steps = [
        f"security add-trusted-cert -r trustRoot -k {keychain} {{certificate}}",
    ]
    if not shutil.which("security"):
        return Target(
            "keychain",
            "The macOS login keychain (Chrome, Safari, Brave)",
            False,
            "the security command is missing",
            keychain,
            steps,
        )
    return Target(
        "keychain",
        "The macOS login keychain (Chrome, Safari, Brave)",
        True,
        "",
        keychain,
        steps,
    )


def _macos_firefox() -> Target:
    profiles = firefox_profiles()
    location = str(profiles[0]) if profiles else "~/.mozilla/firefox/<profile>"
    steps = [
        "Firefox: Settings -> Privacy & Security -> Certificates -> "
        "View Certificates -> Authorities -> Import, and pick {certificate}",
    ]
    return Target(
        "firefox",
        "Firefox (profile certificate database)",
        bool(profiles),
        "" if profiles else "no Firefox profile found",
        location,
        steps,
    )


# ------------------------------------------------------------- windows targets


def _windows_store() -> Target:
    steps = ["certutil -addstore -f Root {certificate}"]
    return Target(
        "system",
        "The Windows certificate store (Chrome, Edge)",
        True,
        "",
        "LocalMachine\\Root",
        steps,
    )


def _windows_firefox() -> Target:
    profiles = firefox_profiles()
    location = str(profiles[0]) if profiles else "%APPDATA%\\Mozilla\\Firefox\\Profiles"
    steps = [
        "Firefox: Settings -> Privacy & Security -> Certificates -> "
        "View Certificates -> Authorities -> Import, and pick {certificate}",
    ]
    return Target(
        "firefox",
        "Firefox (profile certificate database)",
        bool(profiles),
        "" if profiles else "no Firefox profile found",
        location,
        steps,
    )


# --------------------------------------------------------------------- targets


def targets() -> list[Target]:
    """The trust stores that could be used on this machine."""
    system = platform.system()
    if system == "Linux":
        return [_linux_system(), _linux_nss(), _linux_firefox()]
    if system == "Darwin":
        return [_macos_keychain(), _macos_firefox()]
    if system == "Windows":
        return [_windows_store(), _windows_firefox()]
    return [
        Target(
            "manual",
            "No automatic integration for this platform",
            False,
            f"unsupported platform: {system}",
            "",
            ["Import intercept-ca.crt into the browser's authority store by hand"],
        )
    ]


# ------------------------------------------------------------------- installing


def _install_nss(database: Path, certificate: Path) -> str:
    certutil = _certutil()
    assert certutil is not None
    database.mkdir(parents=True, exist_ok=True)
    if not (database / "cert9.db").exists():
        created = _run([certutil, "-N", "-d", f"sql:{database}", "--empty-password"])
        if created.returncode != 0:
            raise RuntimeError(created.stderr.strip() or "certutil could not create the database")
    _run([certutil, "-d", f"sql:{database}", "-D", "-n", CERT_LABEL])
    result = _run(
        [
            certutil,
            "-d",
            f"sql:{database}",
            "-A",
            "-n",
            CERT_LABEL,
            "-t",
            NSS_TRUST,
            "-i",
            str(certificate),
        ]
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "certutil failed")
    return f"installed into {database}"


def _install_linux_system(certificate: Path) -> str:
    store = system_store()
    if store is None:
        raise RuntimeError("the layout of the system trust store is not recognised")
    directory, command = store
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / "intercept-ca.crt"
    shutil.copyfile(certificate, target)
    result = _run(command.split())
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"{command} failed")
    return f"installed into {target}"


def _install_macos_keychain(certificate: Path) -> str:
    keychain = str(_home() / "Library" / "Keychains" / "login.keychain-db")
    result = _run(
        ["security", "add-trusted-cert", "-r", "trustRoot", "-k", keychain, str(certificate)]
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "security failed")
    return f"installed into {keychain}"


def _install_windows_store(certificate: Path) -> str:
    result = _run(["certutil", "-addstore", "-f", "Root", str(certificate)])
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "certutil failed")
    return "installed into the Windows root store"


def install(name: str, certificate: Path) -> str:
    """Install *certificate* into the trust store called *name*."""
    if name == "nss":
        return _install_nss(nss_database(), certificate)
    if name == "firefox":
        profiles = firefox_profiles()
        if not profiles:
            raise RuntimeError("no Firefox profile was found")
        return _install_nss(profiles[0] / "cert9.db", certificate)
    if name == "system":
        if platform.system() == "Darwin":
            return _install_macos_keychain(certificate)
        if platform.system() == "Windows":
            return _install_windows_store(certificate)
        return _install_linux_system(certificate)
    if name == "keychain":
        return _install_macos_keychain(certificate)
    raise RuntimeError(f"unknown target: {name}")


def uninstall(name: str) -> str:
    """Remove the certificate from the trust store called *name*."""
    certutil = _certutil()
    if name == "nss":
        if certutil is None:
            raise RuntimeError("certutil is missing")
        _run([certutil, "-d", f"sql:{nss_database()}", "-D", "-n", CERT_LABEL])
        return f"removed from {nss_database()}"
    if name == "firefox":
        profiles = firefox_profiles()
        if not profiles or certutil is None:
            raise RuntimeError("no Firefox profile or no certutil")
        _run([certutil, "-d", f"sql:{profiles[0] / 'cert9.db'}", "-D", "-n", CERT_LABEL])
        return f"removed from {profiles[0]}"
    if name == "system" and platform.system() == "Linux":
        store = system_store()
        if store is None:
            raise RuntimeError("the layout of the system trust store is not recognised")
        directory, command = store
        target = directory / "intercept-ca.crt"
        if target.exists():
            target.unlink()
            _run(command.split())
        return f"removed from {target}"
    raise RuntimeError(f"the {name} target cannot be removed automatically")
