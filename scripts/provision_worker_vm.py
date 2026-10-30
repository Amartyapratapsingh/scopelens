"""Provision the dedicated scanner VM; keep Docker client keys in ignored runs/ only."""

import io
import ipaddress
import json
import os
import subprocess
import tarfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

VM = "scopelens-workers"
ROOT = Path("runs/worker-vm")


def guest(args, **kwargs):
    return subprocess.run(["limactl", "shell", VM, "--", "sudo", *args], check=True, **kwargs)


def certificates():
    ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    (ROOT / "client").mkdir(exist_ok=True, mode=0o700)
    required = [ROOT / name for name in ("server-cert.pem", "server-key.pem", "ca.pem")]
    required.extend(ROOT / "client" / name for name in ("cert.pem", "key.pem", "ca.pem"))
    if all(path.exists() for path in required):
        return
    if any(path.exists() for path in required):
        raise RuntimeError(
            "Incomplete worker certificates; archive the partial set before renewing"
        )
    now = datetime.now(UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ScopeLens worker VM CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    for kind in ("server", "client"):
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, kind)]))
            .issuer_name(ca.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.ExtendedKeyUsage(
                    [
                        ExtendedKeyUsageOID.SERVER_AUTH
                        if kind == "server"
                        else ExtendedKeyUsageOID.CLIENT_AUTH
                    ]
                ),
                critical=False,
            )
        )
        if kind == "server":
            builder = builder.add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName("host.docker.internal"),
                        x509.DNSName("localhost"),
                        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    ]
                ),
                critical=False,
            )
        prefix = ROOT if kind == "server" else ROOT / "client"
        cert_name, key_name = (
            ("server-cert.pem", "server-key.pem") if kind == "server" else ("cert.pem", "key.pem")
        )
        (prefix / cert_name).write_bytes(
            builder.sign(ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)
        )
        (prefix / key_name).write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        os.chmod(prefix / key_name, 0o600)
        (prefix / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    # No retained CA signing key: renewal replaces this local deployment's certificates.


def main():
    boot = guest(["cat", "/proc/cmdline"], capture_output=True, text=True).stdout
    if "arm64.nosme" not in boot.split():
        guest(
            ["bash", "-s"],
            input=b"""set -eu
mkdir -p /etc/default/grub.d
printf '%s\n' 'GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT arm64.nosme"' > /etc/default/grub.d/scopelens-browser.cfg
update-grub
""",
        )
        subprocess.run(["limactl", "stop", VM], check=True)
        subprocess.run(["limactl", "start", "--tty=false", VM], check=True)
    certificates()
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w") as tar:
        for name in ("ca.pem", "server-cert.pem", "server-key.pem"):
            tar.add(ROOT / name, arcname=name)
        tar.add("deploy/worker_vm/relay.py", arcname="relay.py")
        tar.add("deploy/worker_vm/firewall.sh", arcname="firewall.sh")
    guest(["mkdir", "-p", "/opt/scopelens-worker"])
    guest(["tar", "xf", "-", "-C", "/opt/scopelens-worker"], input=archive.getvalue())
    guest(
        ["bash", "-s"],
        input=b"""set -eu
mkdir -p /etc/systemd/system/docker.service.d
cat > /etc/systemd/system/docker.service.d/scopelens.conf <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/bin/dockerd -H unix:///var/run/docker.sock -H tcp://127.0.0.1:2376 --tlsverify --tlscacert=/opt/scopelens-worker/ca.pem --tlscert=/opt/scopelens-worker/server-cert.pem --tlskey=/opt/scopelens-worker/server-key.pem
EOF
systemctl daemon-reload
systemctl restart docker
""",
    )
    freeze = json.loads(Path("runs/release/freeze.json").read_text())
    refs = [
        freeze["images"][key]
        for key in (
            "SCOPELENS_KALI_WORKER_IMAGE",
            "SCOPELENS_BROWSER_WORKER_IMAGE",
            "SCOPELENS_TOOL_WORKER_IMAGE",
        )
    ]
    save = subprocess.Popen(["docker", "save", *refs], stdout=subprocess.PIPE)
    try:
        guest(["docker", "load"], stdin=save.stdout)
    finally:
        save.stdout.close()
    if save.wait() != 0:
        raise RuntimeError("worker image export failed")
    tool_image = refs[-1]
    guest(
        ["bash", "-s", "--", tool_image],
        input=b"""set -eu
docker network inspect scopelens_worker_net >/dev/null 2>&1 || docker network create --internal --subnet 172.30.0.0/24 --opt com.docker.network.bridge.name=slworker scopelens_worker_net
docker network inspect scopelens_relay_net >/dev/null 2>&1 || docker network create --subnet 172.30.1.0/24 --opt com.docker.network.bridge.name=slrelay scopelens_relay_net
docker rm -f scopelens-proxy-relay >/dev/null 2>&1 || true
docker create --name scopelens-proxy-relay --network scopelens_relay_net --ip 172.30.1.2 --read-only --cap-drop ALL --security-opt no-new-privileges --memory 128m --pids-limit 64 --restart unless-stopped -v /opt/scopelens-worker/relay.py:/relay.py:ro --entrypoint python "$1" /relay.py
docker network connect --ip 172.30.0.2 --alias proxy scopelens_worker_net scopelens-proxy-relay
cat > /etc/systemd/system/scopelens-worker-firewall.service <<'EOF'
[Unit]
After=docker.service
Requires=docker.service
[Service]
Type=oneshot
ExecStart=/bin/sh /opt/scopelens-worker/firewall.sh
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable scopelens-worker-firewall.service
systemctl restart scopelens-worker-firewall.service
docker start scopelens-proxy-relay
""",
    )
    (ROOT / "provision.json").write_text(
        json.dumps(
            {
                "vm": VM,
                "images": refs,
                "source_fingerprint": freeze["source_fingerprint"],
                "status": "provisioned_not_yet_qualified",
            },
            indent=2,
        )
        + "\n"
    )
    print("Worker VM provisioned; qualification must pass before switching the supervisor")


if __name__ == "__main__":
    main()
