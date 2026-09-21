import base64
import hashlib
import hmac
import json
import os

import base58
import nacl.signing
import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from nio import AsyncClient, AsyncClientConfig, JoinResponse

SELF_SIGNING_SECRET = "m.cross_signing.self_signing"
DISPLAY_NAME = "api-account"


def unpadded_b64encode(data):
    return base64.b64encode(data).decode("ascii").rstrip("=")


def b64decode_any(data):
    if isinstance(data, str):
        data = data.encode("ascii")
    return base64.b64decode(data + b"=" * (-len(data) % 4))


def canonical_json(obj):
    return json.dumps(
        obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False
    ).encode("utf-8")


def normalize_homeserver(value):
    value = value.strip()
    if not value.startswith("http"):
        value = "https://" + value
    return value.rstrip("/")


def normalize_room_id(value):
    value = value.strip()
    marker = "/room/"
    if marker in value:
        value = value.split(marker, 1)[1]
    return value.split("?", 1)[0].strip().strip("/")


def decode_recovery_key(recovery_key):
    cleaned = recovery_key.replace(" ", "").strip()
    decoded = base58.b58decode(cleaned)
    if len(decoded) != 35:
        raise ValueError("Recovery key has wrong length")
    if decoded[0] != 0x8B or decoded[1] != 0x01:
        raise ValueError("Recovery key has wrong prefix")
    parity = 0
    for byte in decoded:
        parity ^= byte
    if parity != 0:
        raise ValueError("Recovery key parity check failed")
    return bytes(decoded[2:34])


def derive_keys(ssss_key, name):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=b"\x00" * 32,
        info=name.encode("utf-8"),
    )
    derived = hkdf.derive(ssss_key)
    return derived[:32], derived[32:]


def aes_ctr(aes_key, iv, data):
    worker = Cipher(algorithms.AES(aes_key), modes.CTR(iv)).encryptor()
    return worker.update(data) + worker.finalize()


def compute_mac(mac_key, ciphertext):
    return hmac.new(mac_key, ciphertext, hashlib.sha256).digest()


def matches_recovery_key(ssss_key, key_description):
    if "iv" not in key_description or "mac" not in key_description:
        return True
    iv = b64decode_any(key_description["iv"])
    aes_key, mac_key = derive_keys(ssss_key, "")
    ciphertext = aes_ctr(aes_key, iv, b"\x00" * 32)
    expected = key_description["mac"].rstrip("=")
    actual = unpadded_b64encode(compute_mac(mac_key, ciphertext))
    return hmac.compare_digest(expected, actual)


def decrypt_secret(ssss_key, encrypted, secret_name):
    iv = b64decode_any(encrypted["iv"])
    ciphertext = b64decode_any(encrypted["ciphertext"])
    aes_key, mac_key = derive_keys(ssss_key, secret_name)
    expected = encrypted["mac"].rstrip("=")
    actual = unpadded_b64encode(compute_mac(mac_key, ciphertext))
    if not hmac.compare_digest(expected, actual):
        raise ValueError("MAC mismatch while decrypting " + secret_name)
    return aes_ctr(aes_key, iv, ciphertext)


def sign_object(obj, signing_key, user_id, key_id):
    signatures = obj.pop("signatures", {})
    unsigned = obj.pop("unsigned", None)
    signature = signing_key.sign(canonical_json(obj)).signature
    obj["signatures"] = signatures
    if unsigned is not None:
        obj["unsigned"] = unsigned
    obj["signatures"].setdefault(user_id, {})[key_id] = unpadded_b64encode(signature)
    return obj


def auth_headers(access_token):
    return {"Authorization": "Bearer " + access_token}


def login_password(homeserver, user, password):
    body = {
        "type": "m.login.password",
        "identifier": {"type": "m.id.user", "user": user},
        "password": password,
        "initial_device_display_name": DISPLAY_NAME,
    }
    response = requests.post(
        homeserver + "/_matrix/client/v3/login", json=body, timeout=30
    )
    response.raise_for_status()
    data = response.json()
    return data["access_token"], data["user_id"], data["device_id"]


def whoami_ok(homeserver, access_token, user_id):
    response = requests.get(
        homeserver + "/_matrix/client/v3/account/whoami",
        headers=auth_headers(access_token),
        timeout=30,
    )
    return response.status_code == 200 and response.json().get("user_id") == user_id


def get_account_data(homeserver, access_token, user_id, event_type):
    response = requests.get(
        "{0}/_matrix/client/v3/user/{1}/account_data/{2}".format(
            homeserver, user_id, event_type
        ),
        headers=auth_headers(access_token),
        timeout=30,
    )
    response.raise_for_status()
    return response.json()


def query_own_keys(homeserver, access_token, user_id):
    response = requests.post(
        homeserver + "/_matrix/client/v3/keys/query",
        headers=auth_headers(access_token),
        json={"device_keys": {user_id: []}},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()


def upload_signature(homeserver, access_token, user_id, device_id, signed_device):
    response = requests.post(
        homeserver + "/_matrix/client/v3/keys/signatures/upload",
        headers=auth_headers(access_token),
        json={user_id: {device_id: signed_device}},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()


def unlock_self_signing_key(homeserver, access_token, user_id, ssss_key):
    secret = get_account_data(homeserver, access_token, user_id, SELF_SIGNING_SECRET)
    encrypted_by_key = secret["encrypted"]
    chosen = None
    for key_id, blob in encrypted_by_key.items():
        description = get_account_data(
            homeserver, access_token, user_id, "m.secret_storage.key." + key_id
        )
        if matches_recovery_key(ssss_key, description):
            chosen = blob
            break
    if chosen is None:
        raise SystemExit("Recovery key does not match any storage key for self-signing.")
    seed_b64 = decrypt_secret(ssss_key, chosen, SELF_SIGNING_SECRET)
    seed = b64decode_any(seed_b64.decode("ascii").strip())
    return nacl.signing.SigningKey(seed)


def cross_sign_device(homeserver, access_token, user_id, device_id, recovery_key):
    ssss_key = decode_recovery_key(recovery_key)
    self_signing_key = unlock_self_signing_key(homeserver, access_token, user_id, ssss_key)
    self_signing_public = unpadded_b64encode(bytes(self_signing_key.verify_key))

    keys = query_own_keys(homeserver, access_token, user_id)
    published = keys.get("self_signing_keys", {}).get(user_id, {}).get("keys", {})
    if ("ed25519:" + self_signing_public) not in published:
        raise SystemExit("Decrypted self-signing key does not match the server key.")

    device = keys.get("device_keys", {}).get(user_id, {}).get(device_id)
    if device is None:
        raise SystemExit("Device keys not on server yet; nio must upload them first.")

    signed = sign_object(dict(device), self_signing_key, user_id, "ed25519:" + self_signing_public)
    result = upload_signature(homeserver, access_token, user_id, device_id, signed)
    if result.get("failures"):
        raise SystemExit("Signature upload failures: {0}".format(result["failures"]))

    confirm = query_own_keys(homeserver, access_token, user_id)
    sigs = (
        confirm.get("device_keys", {})
        .get(user_id, {})
        .get(device_id, {})
        .get("signatures", {})
        .get(user_id, {})
    )
    return ("ed25519:" + self_signing_public) in sigs


def load_session(path):
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    return None


def save_session(path, homeserver, user_id, device_id, access_token):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(
            {
                "homeserver": homeserver,
                "user_id": user_id,
                "device_id": device_id,
                "access_token": access_token,
            },
            handle,
        )


def build_nio_client(homeserver, user_id, device_id, access_token, store):
    os.makedirs(store, exist_ok=True)
    config = AsyncClientConfig(store_sync_tokens=True, encryption_enabled=True)
    client = AsyncClient(
        homeserver, user_id, device_id=device_id, store_path=store, config=config
    )
    client.restore_login(
        user_id=user_id, device_id=device_id, access_token=access_token
    )
    return client
