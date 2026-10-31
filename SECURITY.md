# Security and privacy

The HACS integration stores device credentials in its Home Assistant config
entry. The standalone receiver can read an existing config entry. Protect
Home Assistant storage and backups. Give each process access only where required. Device
credentials and account passwords must not be placed in command-line arguments,
issues, workflow configuration or committed files.

The vendor's legacy packet transform and CRC are compatibility mechanisms;
they are not modern authenticated encryption. Use the bridge only for owned
or explicitly authorized devices, and keep player endpoints on a trusted LAN
or private VPN unless separately secured.

Do not attach full Home Assistant configuration, environment dumps, raw logs,
screenshots, video, packet captures, device UIDs or webhook URLs to public
issues. Sample options intentionally write private camera content, despite
using restrictive permissions. The repository's privacy check rejects common
unsafe file types and obvious disclosure patterns, but cannot identify every
possible secret or personal detail.

For a vulnerability, use the repository's private vulnerability reporting
facility if its owner has enabled it. Otherwise contact the maintainer through
an available private channel. A public issue can request private contact
without publishing exploit details or credentials.

The exported stream URL contains a bearer token: anyone with that URL can view
the camera. Keep it out of screenshots, logs and public go2rtc configuration.
Only administrators can generate or rotate it using the integration actions.
Rotating the token invalidates the old URL and disconnects active exports.
Diagnostics deliberately omit device identifiers, credentials and stream URLs.
