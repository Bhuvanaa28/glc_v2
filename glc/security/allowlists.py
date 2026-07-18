"""Per-channel allowlists.

Default posture: empty `allowed_senders` means owner-only for DM channels
and mention-only for public channels (when `mention_only_in_public: true`).
The owner is whichever `channel_user_id` is currently in the pairings
table with trust_level == owner_paired.
"""

from __future__ import annotations

from glc.config import load_channels


def _entry(channel: str) -> dict:
    cfg = load_channels()
    defaults = cfg.get("defaults") or {}
    ch_cfg = (cfg.get("channels") or {}).get(channel) or {}
    out = {
        "allowed_senders": ch_cfg.get("allowed_senders", defaults.get("allowed_senders", [])),
        "mention_only_in_public": ch_cfg.get(
            "mention_only_in_public",
            defaults.get("mention_only_in_public", True),
        ),
        "enabled": ch_cfg.get("enabled", True),
    }
    return out


def allowed(
    channel: str,
    channel_user_id: str,
    *,
    owner_ids: list[str] | None = None,
    is_public_channel: bool = False,
    was_mentioned: bool = False,
) -> tuple[bool, str]:
    """Returns (ok, reason). If the channel itself is disabled, returns False.
    If `owner_ids` is provided, owners always pass. Otherwise, the call is
    allowed if `channel_user_id` is in `allowed_senders`. In public channels
    with mention_only_in_public, an explicit mention is also required."""
    cfg = _entry(channel)
    if not cfg["enabled"]:
        return False, f"channel '{channel}' is disabled in channels.yaml"
    owners = owner_ids or []
    if channel_user_id in owners:
        if is_public_channel and cfg["mention_only_in_public"] and not was_mentioned:
            return False, "owner in public channel must be explicitly mentioned"
        return True, ""
    allowed_list = cfg["allowed_senders"] or []
    if channel_user_id not in allowed_list:
        return False, f"sender {channel_user_id!r} not in allowed_senders for '{channel}'"
    if is_public_channel and cfg["mention_only_in_public"] and not was_mentioned:
        return False, "sender in public channel must be explicitly mentioned"
    return True, ""


def get_egress_hosts(channel: str) -> list[str]:
    """Return the list of permitted outbound hostnames for a given channel adapter."""
    cfg = load_channels()
    defaults = cfg.get("defaults") or {}
    ch_cfg = (cfg.get("channels") or {}).get(channel) or {}
    return ch_cfg.get("egress_hosts", defaults.get("egress_hosts", []))


def check_egress(channel: str, url: str) -> bool:
    """Return True only if the target URL's hostname is in the channel's egress allowlist.

    Deny-by-default: if the allowlist is empty or the hostname is not in it,
    the connection is rejected. Also blocks raw IP addresses in private/reserved ranges.
    """
    import ipaddress
    from urllib.parse import urlparse

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
    except Exception:
        return False

    # Block raw IP address access (private/loopback/link-local/etc.)
    try:
        addr = ipaddress.ip_address(hostname)
        if (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_unspecified
        ):
            return False
    except ValueError:
        pass  # Not an IP, continue with hostname check

    allowed_hosts = get_egress_hosts(channel)
    if not allowed_hosts:
        return False  # Deny by default if no hosts declared

    return any(hostname == h or hostname.endswith("." + h) for h in allowed_hosts)
