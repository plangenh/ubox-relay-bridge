"""Allowlisted diagnostics without credentials, URLs, IDs or camera names."""

from homeassistant.core import HomeAssistant

from . import UBoxConfigEntry


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: UBoxConfigEntry
) -> dict:
    runtime = getattr(entry, "runtime_data", None)
    stats = runtime.manager.diagnostics if runtime else {}
    return {
        "version": "0.1.0",
        "transport_started": runtime is not None
        and runtime.manager.stream_url is not None,
        "counters": {
            key: stats[key]
            for key in (
                "session_attempts",
                "session_failures",
                "session_matched",
                "video_units",
                "video_bytes",
                "datagrams",
                "duplicates",
                "rdt_crc_present",
                "rdt_crc_match",
                "rdt_crc_mismatch",
                "rdt_crc_dropped",
                "slow_consumers",
                "producer_failures",
                "snapshot_failures",
            )
            if isinstance(stats.get(key), int)
        },
    }
