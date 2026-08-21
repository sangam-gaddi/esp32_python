#!/usr/bin/env python3
"""Create a development CA and server certificate for HTTPS OTA.

    python tools/make_dev_certs.py --ip 192.168.1.42

Writes:
    server/certs/ca_key.pem       CA private key   (secret, git-ignored)
    server/certs/ca_cert.pem      CA certificate   (public)
    server/certs/server_key.pem   server key       (secret, git-ignored)
    server/certs/server_cert.pem  server cert, signed by the CA
    main/server_ca_cert.pem       copy of the CA cert, embedded in the firmware

The device pins that single CA certificate and verifies the server against it.
That is the right model for a private server: it needs no public certificate
authority, and it does not require trusting ~200 public roots.

Certificate verification is never disabled on the device. If TLS fails, it fails
closed and the update does not happen.

The --ip value must be the address the ESP32 will connect to, because it goes
into the certificate's subjectAltName and the device checks it.
"""

from __future__ import annotations

import argparse
import datetime
import ipaddress
import pathlib
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

ROOT = pathlib.Path(__file__).resolve().parents[1]
CERTS = ROOT / "server" / "certs"
FIRMWARE_CA = ROOT / "main" / "server_ca_cert.pem"


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ip", action="append", default=[],
                    help="IP address the device will connect to (repeatable). "
                         "Must match OTA_SERVER_URL in main/device_config.h")
    ap.add_argument("--dns", action="append", default=[],
                    help="DNS name to include (repeatable)")
    ap.add_argument("--days", type=int, default=825,
                    help="certificate lifetime in days (default 825)")
    args = ap.parse_args()

    if not args.ip and not args.dns:
        print("error: give at least one --ip or --dns", file=sys.stderr)
        print("       e.g. python tools/make_dev_certs.py --ip 192.168.1.42",
              file=sys.stderr)
        return 2

    sans: list[x509.GeneralName] = []
    for ip in args.ip:
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(ip)))
        except ValueError:
            print(f"error: {ip!r} is not a valid IP address", file=sys.stderr)
            return 2
    for name in args.dns:
        sans.append(x509.DNSName(name))

    CERTS.mkdir(parents=True, exist_ok=True)
    now = datetime.datetime.now(datetime.timezone.utc)
    not_after = now + datetime.timedelta(days=args.days)

    # P-256 rather than RSA: much smaller handshake, and the ESP32 has hardware
    # acceleration for the underlying big-integer maths.
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Secure OTA Development CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure OTA Project"),
    ])
    ca_cert = (x509.CertificateBuilder()
               .subject_name(ca_name)
               .issuer_name(ca_name)
               .public_key(ca_key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(minutes=5))
               .not_valid_after(not_after)
               .add_extension(x509.BasicConstraints(ca=True, path_length=0),
                              critical=True)
               .add_extension(x509.KeyUsage(
                   digital_signature=False, content_commitment=False,
                   key_encipherment=False, data_encipherment=False,
                   key_agreement=False, key_cert_sign=True, crl_sign=True,
                   encipher_only=False, decipher_only=False), critical=True)
               .sign(ca_key, hashes.SHA256()))

    srv_key = ec.generate_private_key(ec.SECP256R1())
    srv_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME,
                           args.dns[0] if args.dns else args.ip[0]),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure OTA Project"),
    ])
    srv_cert = (x509.CertificateBuilder()
                .subject_name(srv_name)
                .issuer_name(ca_name)
                .public_key(srv_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=5))
                .not_valid_after(not_after)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                               critical=True)
                .add_extension(x509.SubjectAlternativeName(sans), critical=False)
                .add_extension(x509.ExtendedKeyUsage(
                    [x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .sign(ca_key, hashes.SHA256()))

    def write(path: pathlib.Path, data: bytes) -> None:
        path.write_bytes(data)
        print(f"  wrote {path.relative_to(ROOT)}")

    pem = serialization.Encoding.PEM
    write(CERTS / "ca_key.pem", ca_key.private_bytes(
        pem, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    ca_pem = ca_cert.public_bytes(pem)
    write(CERTS / "ca_cert.pem", ca_pem)
    write(CERTS / "server_key.pem", srv_key.private_bytes(
        pem, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    write(CERTS / "server_cert.pem", srv_cert.public_bytes(pem))
    write(FIRMWARE_CA, ca_pem)

    names = ", ".join(args.ip + args.dns)
    print(f"\nDevelopment certificates created for: {names}")
    print(f"Valid until {not_after.strftime('%Y-%m-%d')}\n")
    print("Next:")
    print("  1. main/device_config.h ->")
    print(f'       #define OTA_SERVER_URL "https://{(args.ip + args.dns)[0]}:8443"')
    print("  2. rebuild and flash:  idf.py build flash monitor")
    print("     (the CA certificate is embedded at build time)")
    print("  3. start the server:   python server/app.py --https")
    print("\nserver/certs/ is git-ignored. The CA certificate is public, but the")
    print("CA and server private keys are not -- do not commit them.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
