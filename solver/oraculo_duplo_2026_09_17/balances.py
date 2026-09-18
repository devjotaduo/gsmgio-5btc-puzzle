"""Consulta saldos Bitcoin mainnet de chaves hex/WIF/JSONL, sem filtro de alvo.

Derivação local; a API recebe apenas endereços públicos por GET. Nenhuma chave
é escrita nos resultados. Use --dry-run para derivar sem acessar a rede.
"""

from __future__ import annotations

import argparse
import http.client
import json
import math
import re
import socket
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

import base58
from bip_utils import P2TRAddrEncoder, P2WPKHAddrEncoder, SegwitBech32Decoder
from coincurve import PublicKey

from oracle import hash160, valid_scalar

PROVIDERS = {"mempool": "https://mempool.space/api", "blockstream": "https://blockstream.info/api"}
ADDRESS_TYPES = ("p2pkh-compressed", "p2pkh-uncompressed", "p2sh-p2wpkh", "p2wpkh", "p2tr")
KEY_FIELDS = ("private_key", "privkey", "wif")
MAX_LINE = 65536
MAX_RESPONSE = 65536


class InputError(ValueError):
    """Mensagem segura: não inclui o texto da chave ou a linha de entrada."""


class QueryError(Exception):
    """Falha sanitizada; nunca interpreta erro de rede como saldo zero."""


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def btc(satoshis: int) -> str:
    sign = "-" if satoshis < 0 else ""
    whole, fraction = divmod(abs(satoshis), 100_000_000)
    return f"{sign}{whole}.{fraction:08d}"


def parse_key(value: str) -> bytes:
    value = value.strip()
    if value.startswith("0x"):
        value = value[2:]
    if re.fullmatch(r"[0-9a-fA-F]{64}", value):
        secret = bytes.fromhex(value)
    else:
        if not re.fullmatch(r"(?:5[1-9A-HJ-NP-Za-km-z]{50}|[KL][1-9A-HJ-NP-Za-km-z]{51})", value):
            raise InputError("Esperado hex64 ou WIF mainnet válido")
        try:
            payload = base58.b58decode_check(value)
        except ValueError:
            raise InputError("Checksum WIF inválido") from None
        if payload[:1] != b"\x80" or not (len(payload) == 33 or (len(payload) == 34 and payload[-1] == 1)):
            raise InputError("Versão/comprimento/sufixo WIF inválido")
        secret = payload[1:33]
    if not valid_scalar(secret):
        raise InputError("Escalar fora do intervalo secp256k1")
    return secret


def derive_addresses(secret: bytes, kinds: tuple[str, ...] = ADDRESS_TYPES) -> dict[str, str]:
    if not valid_scalar(secret):
        raise InputError("Escalar inválido")
    public = PublicKey.from_valid_secret(secret)
    compressed = public.format(compressed=True)
    digest = hash160(compressed)
    result = {}
    for kind in kinds:
        if kind == "p2pkh-compressed":
            address = base58.b58encode_check(b"\0" + digest).decode("ascii")
        elif kind == "p2pkh-uncompressed":
            address = base58.b58encode_check(b"\0" + hash160(public.format(compressed=False))).decode("ascii")
        elif kind == "p2sh-p2wpkh":
            address = base58.b58encode_check(b"\x05" + hash160(b"\x00\x14" + digest)).decode("ascii")
        elif kind == "p2wpkh":
            address = P2WPKHAddrEncoder.EncodeKey(compressed, hrp="bc")
        elif kind == "p2tr":
            address = P2TRAddrEncoder.EncodeKey(compressed, hrp="bc")
        else:
            raise InputError("Tipo de endereço desconhecido")
        result[kind] = address
    return result


def validate_address(value: str) -> str:
    value = value.strip()
    if not 14 <= len(value) <= 90:
        raise InputError("Endereço Bitcoin mainnet inválido")
    try:
        if value.lower().startswith("bc1"):
            version, program = SegwitBech32Decoder.Decode("bc", value)
            if not ((version == 0 and len(program) in (20, 32)) or (version == 1 and len(program) == 32)):
                raise ValueError
            return value.lower()
        decoded = base58.b58decode_check(value)
        if len(decoded) != 21 or decoded[0] not in (0, 5):
            raise ValueError
        return value
    except (ValueError, TypeError):
        raise InputError("Endereço Bitcoin mainnet inválido") from None


def collect_addresses(files: list[Path], addresses: list[str], kinds: tuple[str, ...], limit: int,
                      max_records: int = 10000) -> list[dict]:
    """Entrada estrita: linhas de chave ou objeto JSONL com exatamente um campo de chave."""
    entries: dict[str, dict] = {}
    records = len(addresses)
    if records > max_records:
        raise InputError("Limite de registros excedido; aumente --max-records explicitamente")

    def add(address: str, reference: dict) -> None:
        if address not in entries:
            if len(entries) >= limit:
                raise InputError("Limite de endereços excedido; aumente --max-addresses explicitamente")
            entries[address] = {"address": address, "origins": []}
        # Cada origem é identificada por arquivo/linha/tipo ou índice de argumento.
        entries[address]["origins"].append(reference)

    for file_number, path in enumerate(files, 1):
        try:
            with path.open("r", encoding="utf-8-sig") as stream:
                line_number = 0
                while raw := stream.readline(MAX_LINE + 1):
                    line_number += 1
                    if len(raw) > MAX_LINE:
                        raise InputError(f"Arquivo {file_number}, linha {line_number}: linha excede 64 KiB")
                    line = raw.strip()
                    if not line or line.startswith("#"):
                        continue
                    records += 1
                    if records > max_records:
                        raise InputError("Limite de registros excedido; aumente --max-records explicitamente")
                    try:
                        if line.startswith("{"):
                            record = json.loads(line)
                            fields = [field for field in KEY_FIELDS if field in record]
                            if len(fields) != 1 or not isinstance(record[fields[0]], str):
                                raise InputError("JSONL requer exatamente um campo private_key, privkey ou wif")
                            line = record[fields[0]]
                        secret = parse_key(line)
                    except (ValueError, TypeError, RecursionError):
                        raise InputError(f"Arquivo {file_number}, linha {line_number}: chave/registro inválido") from None
                    for kind, address in derive_addresses(secret, kinds).items():
                        add(address, {"file_index": file_number, "line": line_number, "type": kind})
        except (OSError, UnicodeError):
            raise InputError(f"Arquivo de chaves {file_number}: não foi possível ler como UTF-8") from None
    for index, address in enumerate(addresses, 1):
        add(validate_address(address), {"address_input": index, "type": "explicit-address"})
    return list(entries.values())


def parse_balance(data: object, address: str) -> dict:
    if not isinstance(data, dict) or data.get("address") != address:
        raise QueryError("invalid_api_address")
    stats = {}
    for name in ("chain_stats", "mempool_stats"):
        value = data.get(name)
        fields = ("funded_txo_sum", "spent_txo_sum", "tx_count")
        if not isinstance(value, dict) or any(type(value.get(key)) is not int or value[key] < 0 for key in fields):
            raise QueryError("invalid_api_stats")
        stats[name] = value
    chain, pool = stats["chain_stats"], stats["mempool_stats"]
    confirmed = chain["funded_txo_sum"] - chain["spent_txo_sum"]
    pending = pool["funded_txo_sum"] - pool["spent_txo_sum"]
    total = confirmed + pending
    if confirmed < 0 or total < 0:
        raise QueryError("inconsistent_api_balance")
    return {"confirmed_sat": confirmed, "confirmed_btc": btc(confirmed),
            "mempool_delta_sat": pending, "mempool_delta_btc": btc(pending),
            "with_mempool_sat": total, "with_mempool_btc": btc(total),
            "received_confirmed_sat": chain["funded_txo_sum"],
            "spent_confirmed_sat": chain["spent_txo_sum"],
            "confirmed_tx_count": chain["tx_count"], "mempool_tx_count": pool["tx_count"],
            "has_history": chain["tx_count"] > 0 or pool["tx_count"] > 0}


class Client:
    def __init__(self, provider: str, timeout: float, interval: float, retries: int,
                 *, opener=None, sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.base = PROVIDERS[provider]
        self.timeout, self.interval, self.retries = timeout, interval, retries
        self.opener = opener if opener is not None else urllib.request.build_opener(NoRedirects())
        self.sleep, self.clock = sleep, clock
        self.next_request = 0.0

    def query(self, address: str) -> dict:
        address = validate_address(address)
        for attempt in range(self.retries + 1):
            delay = self.next_request - self.clock()
            if delay > 0:
                self.sleep(delay)
            request = urllib.request.Request(f"{self.base}/address/{address}",
                                             headers={"Accept": "application/json", "User-Agent": "gsmg-balance-reader/1.0"},
                                             method="GET")
            retry_after = 0.0
            try:
                self.next_request = self.clock() + self.interval
                with self.opener.open(request, timeout=self.timeout) as response:
                    raw = response.read(MAX_RESPONSE + 1)
                if len(raw) > MAX_RESPONSE:
                    raise QueryError("api_response_too_large")
                try:
                    decoded = json.loads(raw)
                except (ValueError, UnicodeError, RecursionError):
                    raise QueryError("invalid_api_json") from None
                return parse_balance(decoded, address)
            except urllib.error.HTTPError as error:
                code = error.code
                header = error.headers.get("Retry-After", "") if error.headers else ""
                error.close()
                failure = f"http_{code}"
                if code != 429 and not 500 <= code <= 599:
                    raise QueryError(failure) from None
                if re.fullmatch(r"[0-9]{1,10}", header):
                    retry_after = min(float(header), 30.0)
            except (urllib.error.URLError, TimeoutError, socket.timeout, OSError, http.client.HTTPException):
                failure = "network_error"
            if attempt == self.retries:
                raise QueryError(failure) from None
            self.sleep(max(min(2 ** attempt, 30), retry_after))
        raise QueryError("retry_limit")


def run(args: argparse.Namespace) -> int:
    rows = collect_addresses(args.keys_file, args.address, tuple(args.types), args.max_addresses, args.max_records)
    if not rows:
        raise InputError("Nenhuma chave/endereço de entrada; nenhum pedido enviado")
    output = args.out.resolve()
    if any(output == path.resolve() for path in args.keys_file):
        raise InputError("A saída não pode substituir arquivo de chaves")
    output.parent.mkdir(parents=True, exist_ok=True)
    client = None if args.dry_run else Client(args.provider, args.timeout, args.interval, args.retries)
    counts = {"addresses": len(rows), "ok": 0, "errors": 0, "derived_only": 0,
              "positive_confirmed": 0, "positive_with_mempool": 0, "with_history": 0}
    # Exclusivo: nunca sobrescreve resultados nem entrada; grava cada consulta concluída.
    with output.open("x", encoding="utf-8") as stream:
        for index, row in enumerate(rows, 1):
            if client is None:
                result = {"status": "derived_only", **row}
                counts["derived_only"] += 1
            else:
                try:
                    balance = client.query(row["address"])
                    result = {"status": "ok", **row, "provider": args.provider,
                              "checked_at_utc": utc_now(), **balance}
                    counts["ok"] += 1
                    counts["positive_confirmed"] += balance["confirmed_sat"] > 0
                    counts["positive_with_mempool"] += balance["with_mempool_sat"] > 0
                    counts["with_history"] += balance["has_history"]
                except QueryError as error:
                    result = {"status": "error", **row, "provider": args.provider,
                              "checked_at_utc": utc_now(), "error": str(error)}
                    counts["errors"] += 1
            stream.write(json.dumps(result, ensure_ascii=False) + "\n")
            stream.flush()
            if result["status"] == "ok":
                print(f"[{index}/{len(rows)}] {row['address']} confirmado={result['confirmed_btc']} BTC "
                      f"com_mempool={result['with_mempool_btc']} BTC", flush=True)
            else:
                print(f"[{index}/{len(rows)}] {row['address']} {result['status']}", flush=True)
    print(json.dumps({"status": "partial" if counts["errors"] else "complete", **counts}), flush=True)
    return 2 if counts["errors"] else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keys-file", type=Path, action="append", default=[], help="UTF-8: hex64/WIF por linha ou JSONL; pode repetir")
    parser.add_argument("--address", action="append", default=[], help="Endereço público mainnet; pode repetir")
    parser.add_argument("--out", required=True, type=Path, help="JSONL novo; contém apenas endereços, origens numéricas e saldos")
    parser.add_argument("--types", nargs="+", choices=ADDRESS_TYPES, default=list(ADDRESS_TYPES))
    parser.add_argument("--provider", choices=PROVIDERS, default="mempool")
    parser.add_argument("--max-addresses", type=int, default=1000)
    parser.add_argument("--max-records", type=int, default=10000, help="Limite de linhas de chave + endereços, incluindo repetições")
    parser.add_argument("--timeout", type=float, default=15)
    parser.add_argument("--interval", type=float, default=1, help="Intervalo mínimo entre pedidos, em segundos")
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("--dry-run", action="store_true", help="Deriva endereços sem consultar a API")
    args = parser.parse_args()
    if not args.keys_file and not args.address:
        parser.error("Informe --keys-file ou --address")
    if (args.max_addresses < 1 or args.max_records < 1 or not 0 <= args.retries <= 5
            or not math.isfinite(args.timeout) or not 0 < args.timeout <= 60
            or not math.isfinite(args.interval) or not 0.1 <= args.interval <= 60):
        parser.error("max-addresses e max-records >= 1; retries 0..5; timeout (0,60]; interval [0.1,60]")
    try:
        return run(args)
    except InputError as error:
        print(f"Erro: {error}", file=sys.stderr)
        return 1
    except OSError:
        print("Erro ao abrir/gravar saída (ela deve ser nova) ou ler os arquivos locais", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Interrompido; consultas já concluídas permanecem no JSONL", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
