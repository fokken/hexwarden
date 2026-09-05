CATEGORY = 'system_hardening'

def run(c):
    c.shell('service list', 'services')
    c.shell('lshal', 'hal_services')
    c.shell('dumpsys keystore2', 'keystore')
    c.shell('ls -lZ /dev/tee* /dev/tpm* /dev/trusty*', 'trust_devices')
    c.shell('find /data/local/tmp /sdcard/Download -maxdepth 3 -type f \( -name "*.pem" -o -name "*.key" -o -name "*.p12" -o -name "*.jks" -o -name ".env" \) -print', 'secret_candidates')
    c.note('Candidate filenames are not proven secrets; private-key contents are not read. KeyMint/Keymaster/StrongBox service presence is not proof of hardware-backed keys. Validate attestation chains, security level and per-key policy using an on-device test app and a trusted verifier. TPM/HSM/vendor integrations need vendor-specific review.')
