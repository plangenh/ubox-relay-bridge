# Security and privacy

This experimental receiver reads device credentials from a selected Home
Assistant config entry. Give the process access only where required. Device
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
