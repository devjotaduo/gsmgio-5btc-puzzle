"""Extrai candidatos textuais hex64/WIF do corpus, sem filtrar pelo prêmio.

Somente leitura dos snapshots. Chaves ficam em keys.jsonl local/ignorado;
extraction.jsonl e spec.json registram proveniência pública, sem segredos.
Não trata janelas raw32 arbitrárias como chaves descobertas.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from contextlib import closing
from pathlib import Path

from balances import derive_addresses
from oracle import Oracle
from partition import readonly
from scan import file_sha256


class CandidateDecoder(Oracle):
    def check(self, secret: bytes) -> list[dict]:
        # Oracle.scan já validou o escalar. Aqui a saída é candidato, não prova.
        return [{"candidate_secret": secret}]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, action="append", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--max-candidates", type=int, default=10000)
    args = parser.parse_args()
    if args.max_candidates < 1 or args.out.exists():
        parser.error("max-candidates deve ser positivo e pasta de saída deve ser nova")
    work = Path(__file__).resolve().parents[2] / "_work"
    if not args.out.resolve().is_relative_to(work.resolve()):
        parser.error("Saída com chaves deve ficar sob _work/ nesta worktree")
    hashes = {str(path.resolve(strict=True)): file_sha256(path) for path in args.corpus}
    decoder = CandidateDecoder()
    candidates: dict[bytes, list[dict]] = {}
    attempts: Counter = Counter()
    payload_count = 0
    for corpus_index, path in enumerate(args.corpus, 1):
        with closing(readonly(path)) as con:
            for identifier, digest, data in con.execute("SELECT id,sha256,data FROM payloads ORDER BY id"):
                if hashlib.sha256(data).hexdigest() != digest:
                    raise ValueError("Hash de payload inválido")
                payload_count += 1
                result = decoder.scan(data, decoded_only=True)
                attempts.update(result["attempts"])
                for item in result["hits"]:
                    secret = item["candidate_secret"]
                    if secret not in candidates:
                        if len(candidates) >= args.max_candidates:
                            raise ValueError("Limite de candidatos excedido")
                        candidates[secret] = []
                    candidates[secret].append({"corpus_index": corpus_index,
                                               "payload_id": identifier, "payload_sha256": digest,
                                               "format": item["format"], "offset": item["offset"]})
    for path, digest in hashes.items():
        if file_sha256(Path(path)) != digest:
            raise ValueError("Corpus alterado durante extração")
    args.out.mkdir(parents=True)
    addresses = set()
    with (args.out / "keys.jsonl").open("x", encoding="utf-8") as private, (args.out / "extraction.jsonl").open("x", encoding="utf-8") as public:
        for index, (secret, occurrences) in enumerate(candidates.items(), 1):
            candidate_id = f"k{index:05d}"
            private.write(json.dumps({"candidate_id": candidate_id, "private_key": secret.hex()}) + "\n")
            derived = derive_addresses(secret)
            addresses.update(derived.values())
            public.write(json.dumps({"candidate_id": candidate_id, "keys_file_line": index,
                                     "addresses": derived, "occurrences": occurrences}) + "\n")
    spec = {"status": "complete", "corpus_sha256": hashes, "payloads_examined": payload_count,
            "textual_attempts": dict(attempts), "candidate_occurrences": sum(map(len, candidates.values())),
            "unique_candidates": len(candidates), "unique_addresses": len(addresses),
            "scope": "hex64/WIF nas visões textuais do oráculo; sem raw32 nem derivação por hashes",
            "limits": "Candidatos podem ser hashes, exemplos, controles ou falsos positivos; não são chaves validadas do puzzle.",
            "extractor_sha256": file_sha256(Path(__file__)),
            "oracle_sha256": file_sha256(Path(__file__).with_name("oracle.py")),
            "balances_sha256": file_sha256(Path(__file__).with_name("balances.py"))}
    (args.out / "spec.json").write_text(json.dumps(spec, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(spec, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
