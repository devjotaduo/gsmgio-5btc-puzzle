"""Consulta endereços públicos extraídos em lotes pela API Blockchain.com.

Entrada: extraction.jsonl, sem chaves. O saldo é o final_balance reportado
pelo provedor; não há separação confirmado/mempool neste endpoint.
"""

from __future__ import annotations

import argparse
import http.client
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path

from balances import ADDRESS_TYPES, NoRedirects, QueryError, btc, utc_now, validate_address
from scan import file_sha256


def load_addresses(path: Path) -> dict[str, list[dict]]:
    rows: dict[str, list[dict]] = {}
    with path.open(encoding="utf-8") as stream:
        line_number = 0
        while line := stream.readline(65537):
            line_number += 1
            if len(line) > 65536 or line_number > 10000:
                raise ValueError("Arquivo excede limites de entrada")
            item = json.loads(line)
            for kind, address in item["addresses"].items():
                if kind not in ADDRESS_TYPES:
                    raise ValueError("Tipo de endereço inválido")
                normalized = validate_address(address)
                rows.setdefault(normalized, []).append({"candidate_line": line_number, "type": kind})
    if not rows:
        raise ValueError("Nenhum endereço")
    return rows


def parse_batch(data: object, expected: list[str]) -> dict[str, dict]:
    if not isinstance(data, dict) or set(data) != set(expected):
        raise QueryError("api_address_set_mismatch")
    result = {}
    for address in expected:
        item = data[address]
        if not isinstance(item, dict) or any(type(item.get(k)) is not int or item[k] < 0
                                             for k in ("final_balance", "n_tx", "total_received")):
            raise QueryError("invalid_api_stats")
        result[address] = {"balance_reported_sat": item["final_balance"],
                           "balance_reported_btc": btc(item["final_balance"]),
                           "tx_count": item["n_tx"], "received_reported_sat": item["total_received"]}
    return result


def query(opener, addresses: list[str]) -> dict[str, dict]:
    url = "https://blockchain.info/balance?" + urllib.parse.urlencode({"active": "|".join(addresses)})
    request = urllib.request.Request(url, headers={"Accept": "application/json",
                                                   "User-Agent": "gsmg-balance-reader/1.0"}, method="GET")
    failure = "network_error"
    for attempt in range(3):
        try:
            with opener.open(request, timeout=20) as response:
                raw = response.read(262145)
            if len(raw) > 262144:
                raise QueryError("api_response_too_large")
            try:
                data = json.loads(raw)
            except (ValueError, RecursionError, UnicodeError):
                raise QueryError("invalid_api_json") from None
            return parse_batch(data, addresses)
        except urllib.error.HTTPError as error:
            code = error.code
            error.close()
            failure = f"http_{code}"
            if code != 429 and not 500 <= code <= 599:
                raise QueryError(failure) from None
        except (urllib.error.URLError, OSError, http.client.HTTPException):
            failure = "network_error"
        if attempt < 2:
            time.sleep(5 * (attempt + 1))
    raise QueryError(failure)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--extraction", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--batch-size", type=int, default=50)
    args = parser.parse_args()
    if args.out.exists() or not 1 <= args.batch_size <= 50:
        parser.error("Saída deve ser pasta nova e batch-size deve estar em 1..50")
    input_hash = file_sha256(args.extraction)
    records = load_addresses(args.extraction)
    addresses = list(records)
    args.out.mkdir(parents=True)
    started = utc_now()
    opener = urllib.request.build_opener(NoRedirects())
    counts: Counter = Counter()
    interesting = []
    with (args.out / "balances.jsonl").open("x", encoding="utf-8") as output:
        for index in range(0, len(addresses), args.batch_size):
            batch = addresses[index:index + args.batch_size]
            before = time.monotonic()
            try:
                results = query(opener, batch)
                error = None
            except QueryError as failure:
                results, error = {}, str(failure)
            checked = utc_now()
            for address in batch:
                row = {"address": address, "origins": records[address], "provider": "blockchain.com",
                       "checked_at_utc": checked}
                if error is not None:
                    row.update({"status": "error", "error": error})
                    counts["errors"] += 1
                else:
                    row.update({"status": "ok", **results[address]})
                    counts["ok"] += 1
                    counts["positive"] += row["balance_reported_sat"] > 0
                    counts["history"] += row["tx_count"] > 0
                    counts["balance_reported_sat"] += row["balance_reported_sat"]
                    if row["balance_reported_sat"] > 0 or row["tx_count"] > 0:
                        interesting.append(row)
                output.write(json.dumps(row) + "\n")
            output.flush()
            print(json.dumps({"processed": min(index + len(batch), len(addresses)),
                              "total": len(addresses), **dict(counts)}), flush=True)
            if index + len(batch) < len(addresses):
                time.sleep(max(0, 1 - (time.monotonic() - before)))
    if file_sha256(args.extraction) != input_hash:
        raise ValueError("Lista de entrada foi alterada")
    summary = {"status": "partial" if counts["errors"] else "complete", "addresses": len(addresses),
               **dict(counts), "started_utc": started, "finished_utc": utc_now(),
               "provider": "blockchain.com", "input_sha256": input_hash,
               "script_sha256": file_sha256(Path(__file__)), "interesting": interesting,
               "balance_semantics": "final_balance reportado; endpoint não separa confirmado/mempool"}
    (args.out / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: value for key, value in summary.items() if key != "interesting"}), flush=True)
    if counts["errors"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
