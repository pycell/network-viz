import subprocess
from collections.abc import Callable
from dataclasses import dataclass

from network_viz.collectors.iptables import parse_iptables_bundle_text
from network_viz.normalizer.model import NormalizedConfig

RemoteRunner = Callable[[str, str, int, str, int], str]


class IptablesSshCollectionError(RuntimeError):
    pass


@dataclass(frozen=True)
class RemoteCommand:
    key: str
    command: str
    required: bool = True


REMOTE_COMMANDS = (
    RemoteCommand("iptables_save", "iptables-save"),
    RemoteCommand("ip_route", "ip route"),
    RemoteCommand("ip_rule", "ip rule"),
    RemoteCommand("ip_addr", "ip -o -4 addr show"),
)


def collect_iptables_over_ssh(
    host: str,
    username: str,
    *,
    port: int = 22,
    timeout_seconds: int = 20,
    runner: RemoteRunner | None = None,
) -> NormalizedConfig:
    if not host.strip():
        raise IptablesSshCollectionError("SSH host is required.")
    if not username.strip():
        raise IptablesSshCollectionError("SSH username is required.")
    if port < 1 or port > 65535:
        raise IptablesSshCollectionError("SSH port must be between 1 and 65535.")

    run = runner or run_remote_command
    outputs: dict[str, str] = {}
    for remote_command in REMOTE_COMMANDS:
        try:
            outputs[remote_command.key] = run(
                host,
                username,
                port,
                remote_command.command,
                timeout_seconds,
            )
        except IptablesSshCollectionError:
            if remote_command.required:
                raise
            outputs[remote_command.key] = ""

    config = parse_iptables_bundle_text(
        outputs["iptables_save"],
        name=f"{username}@{host}:iptables-save",
        route_content=outputs.get("ip_route"),
        rule_content=outputs.get("ip_rule"),
        interface_content=outputs.get("ip_addr"),
    )
    config.source.metadata["collector"] = "ssh"
    config.source.metadata["ssh_host"] = host
    config.source.metadata["ssh_username"] = username
    config.source.metadata["ssh_port"] = port
    return config


def run_remote_command(
    host: str,
    username: str,
    port: int,
    command: str,
    timeout_seconds: int,
) -> str:
    ssh_target = f"{username}@{host}"
    ssh_command = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-p",
        str(port),
        ssh_target,
        command,
    ]
    try:
        completed = subprocess.run(
            ssh_command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except FileNotFoundError as exc:
        raise IptablesSshCollectionError("OpenSSH client was not found on this machine.") from exc
    except subprocess.TimeoutExpired as exc:
        raise IptablesSshCollectionError(
            f"SSH command timed out while running `{command}` on {ssh_target}."
        ) from exc

    if completed.returncode != 0:
        stderr = completed.stderr.strip() or "no stderr"
        raise IptablesSshCollectionError(
            f"SSH command `{command}` failed on {ssh_target}: {stderr}"
        )
    return completed.stdout
