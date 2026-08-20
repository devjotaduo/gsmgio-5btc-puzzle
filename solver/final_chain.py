"""Reproduce the public four-chain GSMG endgame and its hard checkpoints."""

import base64
import hashlib

import base58
from Crypto.Cipher import AES
from Crypto.Hash import MD5

if __package__:
    from . import oracles as O
else:
    import oracles as O


CHAIN1_PASSWORD = b"matrixsumlistenterlastwordsbeforearchichoicethispasswordmatrixsumlist"
CHAIN1_PLAIN = bytes.fromhex(
    "9fa9db91a9dee0e38b93694ec874630b30f32f33671987543b1cf913f4746439"
    "1517389608d55021dc436b66ec513a617c4f14cb0fed4708b535641a6dfe8210"
    "38d4f4c90cb45fdfc8cff50d0ed1c5"
)
CHAIN2_B64 = (
    "U2FsdGVkX1+0Wl49gnWTyiimluu7V3+vl7st0gUt9sWDzNLxDmlPMsDSiuW2a46z"
    "gKlIi8aaqY5gpJPPEzW1n9n3/26qs4zstWtPKF8Zs/BTNN4IiEh4qu18mdC0NAv4"
)
CHAIN2_WIF = b"5K2byJMssxFKuTgnk9YQjpBz5FhkwwF2LaZoAyTus8HjGEpz8AT"
COSMIC_PASSWORD = bytes.fromhex(
    "a795de117e472590e572dc193130c763e3fb555ee5db9d34494e156152e50735"
)
CHAIN4_MASK = bytes.fromhex("b657264f2f6e6921")
CHAIN4_PASSWORD = bytes.fromhex(
    "38d4f4c90cb45fdfc8cff50d0ed1c5"
    "740a25de4b8e946d0a5ae2667a23a2"
    "59cc"
)
COSMIC_SHA256 = "4f7a1e4efe4bf6c5581e32505c019657cb7b030e90232d33f011aca6a5e9c081"
CHAIN2_SHA256 = "b40fce72ef5638e4f79b3233e653f8a5dbdb0d4ae2009d2d3da2c98b70f4d004"
CHAIN4_SHA256 = "e4269ed5fbb202a81e5e1aa6b5190fdd1ea126b2c8547ea7cdbdf45387ea135b"
BLOCKS_SHA256 = "43d3fe43b17ad9e8f5cfa40f35a398fdf32de2fdb18d6261cac283016935c142"
MATRIX_COMPONENTS = bytes.fromhex(
    "0423d9115a1dc756d5d08d2de880ab508bd4745fc97709f4fcb513f2cb8fcc35"
    "48cc46e66bdd36b09ae344552f606a761f9d90681f20dfefe2b43db18b623971"
    "fc0c1b02"
)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _unpad(data: bytes) -> bytes:
    if not data or len(data) % 16:
        raise ValueError("invalid PKCS7 payload length")
    pad = data[-1]
    if not 1 <= pad <= 16 or not data.endswith(bytes([pad]) * pad):
        raise ValueError("invalid PKCS7 padding")
    return data[:-pad]


def decrypt_salted(raw: bytes, password: bytes) -> bytes:
    if len(raw) < 32 or raw[:8] != b"Salted__" or len(raw[16:]) % 16:
        raise ValueError("invalid OpenSSL salted blob")
    key, iv = O._evp(password, raw[8:16], MD5)
    return _unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(raw[16:]))


def wif_uncompressed(private_key: bytes) -> bytes:
    payload = b"\x80" + private_key
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return base58.b58encode(payload + checksum)


def xor_cycle(data: bytes, key: bytes) -> bytes:
    return bytes(value ^ key[index % len(key)] for index, value in enumerate(data))


def matrix_components(cosmic: bytes) -> bytes:
    _require(len(cosmic) == 1327, "Cosmic matrix length mismatch")
    bits = "".join(f"{value:08b}" for value in cosmic)[: 103 * 103]
    row_sums = [sum(map(int, bits[index * 103 : (index + 1) * 103])) for index in range(103)]
    col_sums = [sum(bits[row * 103 + col] == "1" for row in range(103)) for col in range(103)]
    secondary = bytes((row_sums[index] + col_sums[(index + 7) % 103]) & 0xFF for index in range(103))
    digits = [value - 80 for value in secondary]
    _require(all(0 <= digit < 38 for digit in digits), "Matrix output is not base-38")
    number = 0
    for digit in digits:
        number = number * 38 + digit
    decoded = number.to_bytes(68, "big")
    _require(decoded == MATRIX_COMPONENTS, "Matrix component checkpoint mismatch")
    return decoded


def reproduce() -> dict[str, bytes]:
    small_salt, small_ct = O.blobs()["SMALL"]
    chain1 = decrypt_salted(b"Salted__" + small_salt + small_ct, CHAIN1_PASSWORD)
    _require(chain1 == CHAIN1_PLAIN, "Chain 1 checkpoint mismatch")
    _require(wif_uncompressed(chain1[:32]) == CHAIN2_WIF, "Chain 1 WIF mismatch")

    chain2 = decrypt_salted(base64.b64decode(CHAIN2_B64), CHAIN2_WIF)
    _require(hashlib.sha256(chain2).hexdigest() == CHAIN2_SHA256, "Chain 2 checkpoint mismatch")

    cosmic_salt, cosmic_ct = O.blobs()["COSMIC"]
    cosmic = decrypt_salted(b"Salted__" + cosmic_salt + cosmic_ct, COSMIC_PASSWORD)
    _require(len(cosmic) == 1327, "Cosmic length mismatch")
    _require(hashlib.sha256(cosmic).hexdigest() == COSMIC_SHA256, "Cosmic checkpoint mismatch")
    components = matrix_components(cosmic)

    password = chain1[64:79] + chain2[64:79] + cosmic[64:66]
    _require(password == CHAIN4_PASSWORD, "Chain 4 password mismatch")

    # The six K/E fields occupy 158 bytes; the final byte after the mystery
    # payload is the one-byte remainder discarded to recover a block-aligned blob.
    chain4_blob = xor_cycle(cosmic[158:-1], CHAIN4_MASK)
    chain4 = decrypt_salted(chain4_blob, password)
    _require(len(chain4) == 1151, "Chain 4 length mismatch")
    _require(hashlib.sha256(chain4).hexdigest() == CHAIN4_SHA256, "Chain 4 checkpoint mismatch")
    _require(chain4[:2] == b"+-", "Chain 4 marker mismatch")
    _require(len(chain4[31:]) == 35 * 32, "Chain 4 block layout mismatch")
    _require(hashlib.sha256(chain4[31:]).hexdigest() == BLOCKS_SHA256, "Chain 4 blocks mismatch")

    return {
        "chain1": chain1,
        "chain2": chain2,
        "cosmic": cosmic,
        "half": components[:32],
        "better_half": components[32:64],
        "matrix_tail": components[64:],
        "chain4_blob": chain4_blob,
        "chain4": chain4,
        "header": chain4[:31],
        "blocks": chain4[31:],
    }


if __name__ == "__main__":
    result = reproduce()
    for name in (
        "chain1", "chain2", "cosmic", "half", "better_half", "matrix_tail",
        "chain4_blob", "chain4", "blocks",
    ):
        data = result[name]
        print(f"{name}: {len(data)} bytes sha256={hashlib.sha256(data).hexdigest()}")
    print("header.hex:", result["header"].hex())
    print("header.ascii:", result["header"].decode("ascii", "replace"))
