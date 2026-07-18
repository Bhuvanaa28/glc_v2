"""
Modal Sandbox adapter send functions.

Each channel adapter's outbound send() operation runs inside its own
Modal function configured with network_access=modal.NetworkAccess(allow_net=[...]).

This enforces egress allowlists at the infrastructure/OS layer, making it
impossible for a compromised adapter to exfiltrate data outside the allowlist
even via monkeypatching or in-process exploitation.

The gateway's channel_webhook route dispatches to these sandboxed functions
(when GLC_ENV == "production"). In test/dev, adapter.send() is called directly.
"""

from __future__ import annotations

import modal
from pathlib import Path

from modal_app import app, image, data_volume, install_token_secret, llm_secret

LOCAL_GLC = Path(__file__).parent / "glc"

# ---------------------------------------------------------------------------
# Per-channel egress allowlists (mirrors glc/channels.yaml egress_hosts).
# These MUST be kept in sync with channels.yaml.
# ---------------------------------------------------------------------------
_EGRESS: dict[str, list[str]] = {
    "telegram":     ["api.telegram.org"],
    "discord":      ["discord.com", "discordapp.com"],
    "slack":        ["slack.com", "api.slack.com", "hooks.slack.com"],
    "whatsapp":     ["graph.facebook.com", "api.twilio.com"],
    "teams":        ["graph.microsoft.com", "smba.trafficmanager.net",
                     "login.microsoftonline.com", "api.botframework.com"],
    "matrix":       [],   # operator-configured homeserver
    "line":         ["api.line.me"],
    "signal":       [],
    "gmail":        ["www.googleapis.com", "gmail.googleapis.com", "oauth2.googleapis.com"],
    "imap":         [],
    "twilio_sms":   ["api.twilio.com"],
    "twilio_voice": ["api.twilio.com"],
    "webui":        [],
    "webhook":      [],   # operator must configure via env/channels.yaml
    "local_mic":    [],
}


def _make_adapter_send_fn(channel: str):
    """Return a Modal function that sandboxes adapter.send() for one channel."""

    @app.function(
        image=image,
        volumes={"/data": data_volume},
        secrets=[llm_secret, install_token_secret],
        network_access=modal.NetworkAccess(allow_net=_EGRESS.get(channel, [])),
        name=f"adapter_send_{channel}",
    )
    def _adapter_send(reply_dict: dict) -> dict:
        """Run adapter.send() isolated inside a network-restricted sandbox."""
        import asyncio
        from glc.channels import registry
        from glc.channels.envelope import ChannelReply

        adapter = registry.instantiate(channel)
        reply = ChannelReply.model_validate(reply_dict)
        result = asyncio.get_event_loop().run_until_complete(adapter.send(reply))
        return result if isinstance(result, dict) else {"status": "ok"}

    return _adapter_send


# Build one sandboxed function per channel and expose them in a registry.
# Gateway code imports this dict and calls the correct function by name.
SANDBOX_SEND: dict[str, object] = {
    ch: _make_adapter_send_fn(ch) for ch in _EGRESS
}
