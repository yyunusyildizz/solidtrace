# generate_keys.py
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import base64

private_key = Ed25519PrivateKey.generate()
private_bytes = private_key.private_bytes_raw()
public_bytes = private_key.public_key().public_bytes_raw()

print("PRIVATE:", base64.b64encode(private_bytes).decode())
print("PUBLIC :", base64.b64encode(public_bytes).decode())