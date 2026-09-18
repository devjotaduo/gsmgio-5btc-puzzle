"""Oráculo P2PKH isolado: dois endereços, bytes brutos, hex64 e WIF.

Não importa nem altera gsmg_common/oracles e não realiza operações de rede.
O segundo alvo é o destino dos halvings, não um prêmio adicional comprovado.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Iterator

import base58
from coincurve import PublicKey

TARGETS = (
    "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe",
    "17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa",
)
ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
ORDER_BYTES = ORDER.to_bytes(32, "big")
ZERO = bytes(32)
HEX_RUN = re.compile(rb"[0-9A-Fa-f]{64,}")
WIF = re.compile(rb"(?=(5[1-9A-HJ-NP-Za-km-z]{50}|[KL][1-9A-HJ-NP-Za-km-z]{51}))")


def _cp273_inverse_table() -> bytes:
    """Latin-1 → cp273, um byte por posição; falhas viram delimitadores ASCII."""
    mapped = bytearray()
    for value in range(256):
        try:
            mapped.extend(chr(value).encode("cp273"))
        except UnicodeEncodeError:
            # errors='replace' produziria cp273('?') = 0x6f, letra WIF ASCII.
            # '?' ASCII não pertence aos alfabetos hex/WIF e não junta trechos.
            mapped.append(ord("?"))
    return bytes(mapped)


CP273_INVERSE_TABLE = _cp273_inverse_table()


def cp273_inverse_view(buf: bytes) -> bytes:
    """Desfaz ASCII.decode(cp273).encode(latin-1), como na fase 3.2 real."""
    return buf.translate(CP273_INVERSE_TABLE)


def hash160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def address_payload(address: str) -> bytes:
    payload = base58.b58decode_check(address)
    if len(payload) != 21 or payload[0] != 0:
        raise ValueError("O alvo precisa ser um endereço P2PKH Bitcoin mainnet válido")
    return payload[1:]


def valid_scalar(secret: bytes) -> bool:
    return len(secret) == 32 and ZERO < secret < ORDER_BYTES


def decoded_candidates(buf: bytes) -> Iterator[tuple[str, int, bytes]]:
    """Hex64 em todo offset de nibble; WIF com checksum/versão/sufixo válidos."""
    for match in HEX_RUN.finditer(buf):
        run = match.group()
        for index in range(len(run) - 63):
            yield "hex64", match.start() + index, bytes.fromhex(run[index:index + 64].decode("ascii"))
    for match in WIF.finditer(buf):
        try:
            payload = base58.b58decode_check(match.group(1))
        except ValueError:
            continue
        if payload[:1] != b"\x80":
            continue
        if len(payload) == 33:
            yield "wif-uncompressed", match.start(), payload[1:]
        elif len(payload) == 34 and payload[-1] == 1:
            yield "wif-compressed", match.start(), payload[1:33]


class Oracle:
    """Compara hash160 integral das duas serializações sem reduzir escalares."""

    def __init__(self, targets: Iterable[str] = TARGETS) -> None:
        self.targets = tuple(targets)
        if not self.targets or len(set(self.targets)) != len(self.targets):
            raise ValueError("Informe alvos distintos e não vazios")
        self.by_hash = {address_payload(address): address for address in self.targets}

    def check(self, secret: bytes) -> list[dict]:
        if not valid_scalar(secret):
            return []
        public = PublicKey.from_valid_secret(secret).format(compressed=False)
        compressed = bytes((2 | (public[-1] & 1),)) + public[1:33]
        hits = []
        for is_compressed, encoded in ((False, public), (True, compressed)):
            digest = hash160(encoded)
            target = self.by_hash.get(digest)
            if target is not None:
                hits.append({"address": target, "compressed": is_compressed,
                             "hash160": digest.hex(), "public_key": encoded.hex(),
                             "private_key": secret.hex()})
        return hits

    def scan(self, buf: bytes, *, decoded_only: bool = False) -> dict:
        """Varre raw32, ASCII, ambos os sentidos cp273 e UTF-16, com offsets exatos.

        Nas visões transcodificadas, caracteres não ASCII viram '?' (delimitador),
        preservando índices e impedindo que trechos separados sejam concatenados.
        decoded_only omite somente as janelas raw32, não os codecs textuais.
        """
        hits: list[dict] = []
        attempts = {"raw32": 0, "hex64": 0, "wif-uncompressed": 0, "wif-compressed": 0}
        valid = 0

        def check(kind: str, offset: int, secret: bytes) -> None:
            nonlocal valid
            attempts[kind] = attempts.get(kind, 0) + 1
            if not valid_scalar(secret):
                return
            valid += 1
            for hit in self.check(secret):
                hits.append({"format": kind, "offset": offset, **hit})

        if not decoded_only:
            for offset in range(max(0, len(buf) - 31)):
                check("raw32", offset, buf[offset:offset + 32])
        for kind, offset, secret in decoded_candidates(buf):
            check(kind, offset, secret)
        cp273 = buf.decode("cp273").encode("ascii", errors="replace")
        for kind, offset, secret in decoded_candidates(cp273):
            check("cp273:" + kind, offset, secret)
        for kind, offset, secret in decoded_candidates(cp273_inverse_view(buf)):
            check("cp273-inverse:" + kind, offset, secret)
        for codec in ("utf-16-le", "utf-16-be"):
            for alignment in (0, 1):
                end = len(buf) - ((len(buf) - alignment) % 2)
                if end <= alignment:
                    continue
                # surrogatepass mantém um code unit por caráter, inclusive inválidos.
                view = buf[alignment:end].decode(codec, errors="surrogatepass")
                # Pares de surrogates válidos colapsam em um caráter em Python;
                # para offsets exatos, usa-se cada code unit isoladamente.
                if len(view) != (end - alignment) // 2:
                    byteorder = "little" if codec.endswith("le") else "big"
                    view = "".join(chr(int.from_bytes(buf[i:i + 2], byteorder))
                                   for i in range(alignment, end, 2))
                encoded = view.encode("ascii", errors="replace")
                for kind, offset, secret in decoded_candidates(encoded):
                    check(f"{codec}@{alignment}:{kind}", alignment + 2 * offset, secret)
        return {"attempts": attempts, "valid_scalars": valid, "hits": hits}


def independent_address(secret: bytes, compressed: bool) -> str:
    """Conferência por python-ecdsa, independente de libsecp256k1/coincurve."""
    from ecdsa import SECP256k1, SigningKey

    if not valid_scalar(secret):
        raise ValueError("Escalar inválido")
    xy = SigningKey.from_string(secret, curve=SECP256k1).verifying_key.to_string()
    public = bytes((2 | (xy[-1] & 1),)) + xy[:32] if compressed else b"\x04" + xy
    return base58.b58encode_check(b"\x00" + hash160(public)).decode("ascii")
