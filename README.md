

## Limits (read before relying on it)
- **Signing key**: only outside the agent's reach if you keep the owner-held key (setup.ps1 -Auto) on a USB stick or another machine. The default mode is sealed by the OS for the same user, so a fully hijacked agent could unseal it.
- **Anchor**: the log anchor leaves the machine only when a notify channel (e.g. a Telegram script) is configured; otherwise it stays local. Keep that notify script out of the agent's write access.
