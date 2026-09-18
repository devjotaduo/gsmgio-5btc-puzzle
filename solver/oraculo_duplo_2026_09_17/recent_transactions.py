"""Consulta a primeira página de transações dos endereços públicos com histórico."""

from __future__ import annotations

import argparse
import http.client
import json
import re
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from balances import NoRedirects, QueryError, btc, utc_now, validate_address
from scan import file_sha256


def movement(tx: dict, address: str) -> dict:
    if not isinstance(tx, dict) or not re.fullmatch(r"[0-9a-f]{64}", tx.get("txid", "")):
        raise ValueError("Transação inválida")
    received = spent = 0
    for item in tx["vin"]:
        previous = item.get("prevout")
        if previous is None:
            if item.get("is_coinbase") is not True:
                raise ValueError("Prevout ausente")
            continue
        if previous.get("scriptpubkey_address") == address:
            if type(previous.get("value")) is not int or previous["value"] < 0:
                raise ValueError("Valor de entrada inválido")
            spent += previous["value"]
    for item in tx["vout"]:
        if item.get("scriptpubkey_address") == address:
            if type(item.get("value")) is not int or item["value"] < 0:
                raise ValueError("Valor de saída inválido")
            received += item["value"]
    if not received and not spent:
        raise ValueError("Transação não contém movimento de valor para o endereço")
    status = tx["status"]
    if type(status.get("confirmed")) is not bool:
        raise ValueError("Confirmação inválida")
    block_time = status.get("block_time") if status["confirmed"] else None
    if status["confirmed"] and (type(block_time) is not int or block_time < 0):
        raise ValueError("Horário de bloco inválido")
    net = received - spent
    return {"address": address, "txid": tx["txid"], "confirmed": status["confirmed"],
            "block_time": block_time,
            "date_utc": datetime.fromtimestamp(block_time, timezone.utc).isoformat() if block_time is not None else None,
            "received_sat": received, "spent_inputs_sat": spent,
            "net_sat": net, "net_btc": btc(net),
            "direction": "entrada" if net > 0 else "saída" if net < 0 else "neutro",
            "explorer_url": f"https://mempool.space/tx/{tx['txid']}"}


def fetch(opener, address: str) -> list:
    request = urllib.request.Request(f"https://mempool.space/api/address/{address}/txs",
                                     headers={"Accept": "application/json", "User-Agent": "gsmg-balance-reader/1.0"}, method="GET")
    error_code = "network_error"
    for attempt in range(3):
        try:
            with opener.open(request, timeout=25) as response:
                raw = response.read(16 * 1024 * 1024 + 1)
            if len(raw) > 16 * 1024 * 1024:
                raise QueryError("response_too_large")
            result = json.loads(raw)
            if not isinstance(result, list) or len(result) > 75:
                raise QueryError("invalid_transaction_page")
            return result
        except urllib.error.HTTPError as error:
            code = error.code
            error.close()
            error_code = f"http_{code}"
            if code != 429 and not 500 <= code <= 599:
                raise QueryError(error_code) from None
        except (urllib.error.URLError, OSError, http.client.HTTPException):
            error_code = "network_error"
        except (ValueError, RecursionError):
            raise QueryError("invalid_json") from None
        if attempt < 2:
            time.sleep(3 * (attempt + 1))
    raise QueryError(error_code)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--balances", type=Path, required=True, help="verification.jsonl de balances.py")
    parser.add_argument("--out", type=Path, required=True, help="Pasta nova")
    args = parser.parse_args()
    if args.out.exists():
        parser.error("Pasta de saída deve ser nova")
    source_hash = file_sha256(args.balances)
    source = [json.loads(line) for line in args.balances.read_text(encoding="utf-8").splitlines()]
    addresses = sorted({validate_address(item["address"]) for item in source
                        if item.get("status") == "ok" and item.get("has_history") is True})
    if not addresses or len(addresses) > 100:
        parser.error("Entrada precisa conter 1..100 endereços com histórico")
    args.out.mkdir(parents=True)
    opener = urllib.request.build_opener(NoRedirects())
    movements = []
    pages = []
    for index, address in enumerate(addresses, 1):
        started = time.monotonic()
        transactions = fetch(opener, address)
        identifiers = [tx["txid"] for tx in transactions]
        if len(identifiers) != len(set(identifiers)) or not transactions:
            raise ValueError("Página vazia ou com duplicatas")
        page = {"address": address, "queried_utc": utc_now(), "transactions": transactions}
        raw_path = args.out / f"page_{index:02d}.json"
        raw_path.write_text(json.dumps(page) + "\n", encoding="utf-8")
        rows = [movement(tx, address) for tx in transactions]
        movements.extend(rows)
        confirmed = sorted((row for row in rows if row["confirmed"]), key=lambda row: row["block_time"], reverse=True)
        pages.append({"address": address, "page_sha256": file_sha256(raw_path),
                      "confirmed_fetched": len(confirmed), "pending_fetched": len(rows) - len(confirmed),
                      "latest_confirmed": confirmed[0] if confirmed else None})
        print(json.dumps({"processed": index, "addresses": len(addresses), "transactions": len(rows),
                          "latest_confirmed": confirmed[0] if confirmed else None}, ensure_ascii=False), flush=True)
        if index < len(addresses):
            time.sleep(max(0, 1 - (time.monotonic() - started)))
    if file_sha256(args.balances) != source_hash:
        raise ValueError("Entrada alterada")
    confirmed = sorted((row for row in movements if row["confirmed"]), key=lambda row: row["block_time"], reverse=True)
    summary = {"status": "complete", "checked_at_utc": utc_now(), "address_count": len(addresses),
               "balance_input_sha256": source_hash, "script_sha256": file_sha256(Path(__file__)),
               "pages": pages, "most_recent_confirmed": confirmed[:20],
               "pending": [row for row in movements if not row["confirmed"]],
               "limits": "Primeira página por endereço; não é histórico completo. Datas são timestamps de bloco UTC; valores são a variação líquida no endereço, não o total da transação."}
    (args.out / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (args.out / "movements.jsonl").write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in movements), encoding="utf-8")


if __name__ == "__main__":
    main()
