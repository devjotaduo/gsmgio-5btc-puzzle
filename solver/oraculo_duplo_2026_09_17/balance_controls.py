"""Controles offline de derivação, saldos, falhas de API e ausência de segredos."""

import argparse
import contextlib
import http.client
import io
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

import base58
from bip_utils import Bip39SeedGenerator, Bip44Changes, Bip86, Bip86Coins

import balances as B
from oracle import ORDER, independent_address

SECRET = (1).to_bytes(32, "big")  # Vetor público; nunca uma chave de usuário.
ADDRESS = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"


def response(address=ADDRESS, funded=100, spent=20, pending_in=10, pending_out=60):
    return {"address": address,
            "chain_stats": {"funded_txo_sum": funded, "spent_txo_sum": spent, "tx_count": 3},
            "mempool_stats": {"funded_txo_sum": pending_in, "spent_txo_sum": pending_out, "tx_count": 1}}


class FakeOpener:
    def __init__(self, *events):
        self.events = iter(events)
        self.requests = []

    def open(self, request, timeout):
        self.requests.append(request)
        event = next(self.events)
        if isinstance(event, Exception):
            raise event
        return io.BytesIO(event)


class BalanceControls(unittest.TestCase):
    def test_address_vectors_and_independent_ecc(self):
        actual = B.derive_addresses(SECRET)
        self.assertEqual(actual, {
            "p2pkh-compressed": ADDRESS,
            "p2pkh-uncompressed": "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm",
            "p2sh-p2wpkh": "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN",
            "p2wpkh": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            "p2tr": "bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sspknck9",
        })
        for address in actual.values():
            self.assertEqual(B.validate_address(address), address)
            self.assertEqual(B.validate_address(" " + address + "\r\n"), address)
        self.assertEqual(actual["p2pkh-compressed"], independent_address(SECRET, True))
        self.assertEqual(actual["p2pkh-uncompressed"], independent_address(SECRET, False))
        # Primeiro endereço BIP86 oficial: m/86'/0'/0'/0/0.
        seed = Bip39SeedGenerator("abandon " * 11 + "about").Generate("")
        key = (Bip86.FromSeed(seed, Bip86Coins.BITCOIN).Purpose().Coin().Account(0)
               .Change(Bip44Changes.CHAIN_EXT).AddressIndex(0).PrivateKey().Raw().ToBytes())
        self.assertEqual(B.derive_addresses(key)["p2tr"],
                         "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr")

    def test_key_formats_and_invalid_inputs(self):
        for suffix in (b"", b"\x01"):
            wif = base58.b58encode_check(b"\x80" + SECRET + suffix).decode()
            self.assertEqual(B.parse_key(wif), SECRET)
            with self.assertRaises(B.InputError):
                B.parse_key(wif[:-1] + ("1" if wif[-1] != "1" else "2"))
        self.assertEqual(B.parse_key("0x" + SECRET.hex()), SECRET)
        for bad in (bytes(32).hex(), ORDER.to_bytes(32, "big").hex(), "ff" * 32,
                    base58.b58encode_check(b"\xef" + SECRET + b"\x01").decode()):
            with self.assertRaises(B.InputError):
                B.parse_key(bad)
        for bad in (ADDRESS + "/../tx", ADDRESS[:-1] + "1", "bc1WRONG", "not-an-address"):
            with self.assertRaises(B.InputError):
                B.validate_address(bad)

    def test_balances_and_schema(self):
        parsed = B.parse_balance(response(), ADDRESS)
        self.assertEqual((parsed["confirmed_sat"], parsed["mempool_delta_sat"], parsed["with_mempool_sat"]), (80, -50, 30))
        self.assertEqual(parsed["mempool_delta_btc"], "-0.00000050")
        self.assertEqual(B.btc(2100000000000000), "21000000.00000000")
        for malformed in ({}, {"address": ADDRESS}, response(address="wrong"),
                          response(funded=True), response(spent=101), response(pending_out=1000)):
            with self.assertRaises(B.QueryError):
                B.parse_balance(malformed, ADDRESS)

    def test_api_retry_and_only_public_get(self):
        retry = urllib.error.HTTPError("https://mempool.space", 429, "ignored", {"Retry-After": "2"}, None)
        opener = FakeOpener(retry, json.dumps(response()).encode())
        clock = [0.0]

        def sleep(seconds):
            clock[0] += seconds

        client = B.Client("mempool", 5, 1, 2, opener=opener, sleep=sleep, clock=lambda: clock[0])
        self.assertEqual(client.query(ADDRESS)["confirmed_sat"], 80)
        self.assertEqual(len(opener.requests), 2)
        self.assertGreaterEqual(clock[0], 2)
        for request in opener.requests:
            self.assertEqual(request.full_url, "https://mempool.space/api/address/" + ADDRESS)
            self.assertEqual(request.get_method(), "GET")
            self.assertIsNone(request.data)

    def test_errors_are_not_zero_balances(self):
        for failure in (b"not-json", b"{}", b"[" * 1200 + b"0" + b"]" * 1200,
                        b"x" * (B.MAX_RESPONSE + 1),
                        urllib.error.HTTPError("ignored", 404, "ignored", {}, None),
                        http.client.IncompleteRead(b"incomplete"),
                        urllib.error.URLError("sensitive error detail")):
            with self.assertRaises(B.QueryError) as caught:
                B.Client("mempool", 5, 1, 0, opener=FakeOpener(failure)).query(ADDRESS)
            self.assertNotIn("sensitive", str(caught.exception))
        self.assertIsNone(B.NoRedirects().redirect_request(None, None, 302, "", {}, "http://example.com"))

    def test_file_dedup_dry_run_output_and_limits(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            keys = root / "keys.txt"
            wif = base58.b58encode_check(b"\x80" + SECRET + b"\x01").decode()
            keys.write_text(SECRET.hex() + "\n" + json.dumps({"wif": wif, "label": wif}) + "\n", encoding="utf-8")
            rows = B.collect_addresses([keys], [], B.ADDRESS_TYPES, 5)
            self.assertEqual(len(rows), 5)
            self.assertEqual(len(rows[0]["origins"]), 2)
            with self.assertRaises(B.InputError):
                B.collect_addresses([keys], [], B.ADDRESS_TYPES, 4)
            with self.assertRaises(B.InputError):
                B.collect_addresses([keys], [], B.ADDRESS_TYPES, 5, max_records=1)
            args = argparse.Namespace(keys_file=[keys], address=[], types=B.ADDRESS_TYPES,
                                      max_addresses=5, max_records=100, out=root / "out.jsonl", dry_run=True)
            stdout = io.StringIO()
            with patch.object(B, "Client", side_effect=AssertionError("Não pode usar rede")), contextlib.redirect_stdout(stdout):
                self.assertEqual(B.run(args), 0)
            rendered = args.out.read_text(encoding="utf-8") + stdout.getvalue()
            for sensitive in (SECRET.hex(), wif, "private_key", "label"):
                self.assertNotIn(sensitive, rendered)
            with self.assertRaises(FileExistsError):
                B.run(args)
            keys.write_text('{"private_key":"SECRET_TEST_INVALID"}\n', encoding="utf-8")
            with self.assertRaises(B.InputError) as caught:
                B.collect_addresses([keys], [], B.ADDRESS_TYPES, 5)
            self.assertNotIn("SECRET_TEST_INVALID", str(caught.exception))
            keys.write_text('{"private_key":' + '[' * 1200 + '0' + ']' * 1200 + '}\n', encoding="utf-8")
            with self.assertRaises(B.InputError):
                B.collect_addresses([keys], [], B.ADDRESS_TYPES, 5)

    def test_error_row_has_no_balance_and_next_query_continues(self):
        with tempfile.TemporaryDirectory() as temporary:
            second = B.derive_addresses(SECRET)["p2pkh-uncompressed"]
            args = argparse.Namespace(keys_file=[], address=[ADDRESS, second], types=B.ADDRESS_TYPES,
                                      max_addresses=5, max_records=100, out=Path(temporary) / "out.jsonl",
                                      dry_run=False, provider="mempool", timeout=5, interval=1, retries=0)
            with patch.object(B, "Client") as fake, contextlib.redirect_stdout(io.StringIO()):
                fake.return_value.query.side_effect = [B.QueryError("network_error"), B.parse_balance(response(address=second), second)]
                self.assertEqual(B.run(args), 2)
            rows = [json.loads(line) for line in args.out.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(rows[0]["status"], "error")
            self.assertNotIn("confirmed_sat", rows[0])
            self.assertEqual(rows[1]["confirmed_sat"], 80)


if __name__ == "__main__":
    unittest.main(verbosity=2)
