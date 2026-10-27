from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


KEYS_DIR = Path("keys")
PRIVATE_PATH = KEYS_DIR / "rsa_private.pem"
PUBLIC_PATH = KEYS_DIR / "rsa_public.pem"


def main():
    KEYS_DIR.mkdir(parents=True, exist_ok=True)

    if PRIVATE_PATH.exists() or PUBLIC_PATH.exists():
        raise SystemExit(
            "RSA keys already exist. Refusing to overwrite them."
        )

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    PRIVATE_PATH.write_bytes(private_pem)
    PRIVATE_PATH.chmod(0o600)

    PUBLIC_PATH.write_bytes(public_pem)

    print("RSA keys generated successfully")
    print(f"Private: {PRIVATE_PATH}")
    print(f"Public:  {PUBLIC_PATH}")


if __name__ == "__main__":
    main()  