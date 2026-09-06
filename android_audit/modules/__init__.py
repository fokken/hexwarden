from importlib import import_module

NAMES = (
    "developer_options", "screen_lock", "encryption", "unknown_sources", "outdated_os",
    "backup", "logging_secrets", "network", "passive_network", "bluetooth", "certificates",
    "privileged_apis", "filesystem_acls", "custom_permissions", "usb", "secrets_trust",
    "verified_boot", "updates_integrity", "app_extraction", "app_apis",
    "radamsa_fuzz",
)

def registry():
    return {name: import_module(f"android_audit.modules.{name}") for name in NAMES}
