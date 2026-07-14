# -*- coding: utf-8 -*-
"""
Launcher unico do solver GSMG. Sobe os motores que rodam "incansavelmente"
ate um oraculo duro fechar (SOLVED.json) ou serem parados (Ctrl-C).

Motores:
  gpu  -> gpu_search.py : criptanalise Bifid batelada na GPU (periodos curtos),
          o unico com gradiente. Requer torch+CUDA.
  cpu  -> runner.py     : Llama propoe hipoteses DSL + gerador enumerativo +
          oraculos AES/priv/bip39 (familias que a GPU nao cobre).

Uso:
  python launch.py            # sobe gpu + cpu (recomendado)
  python launch.py --only gpu
  python launch.py --only cpu
  python launch.py --status   # imprime status/heartbeats e para
Parar: Ctrl-C (encerra os dois). O estado fica em solver/out/.
"""
import os, sys, json, time, subprocess, argparse, signal

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out"); os.makedirs(OUT, exist_ok=True)
PY = sys.executable

def print_status():
    for f, label in (("gpu_status.json", "GPU-Bifid"), ("status.json", "CPU-Llama")):
        p = os.path.join(OUT, f)
        if os.path.exists(p):
            d = json.load(open(p, encoding="utf-8"))
            print(f"[{label}] {json.dumps(d, ensure_ascii=False)}")
        else:
            print(f"[{label}] (sem heartbeat ainda)")
    sp = os.path.join(OUT, "SOLVED.json")
    if os.path.exists(sp):
        print("\n*** SOLVED.json EXISTE ***")
        print(open(sp, encoding="utf-8").read())
    for f in ("gpu_candidates.jsonl", "candidates.jsonl"):
        p = os.path.join(OUT, f)
        if os.path.exists(p):
            n = sum(1 for _ in open(p, encoding="utf-8"))
            print(f"[{f}] {n} candidatos de legibilidade (revisao humana)")

def solved():
    return os.path.exists(os.path.join(OUT, "SOLVED.json"))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", choices=["gpu", "cpu"], help="rodar so um motor")
    ap.add_argument("--status", action="store_true", help="imprimir status e sair")
    a = ap.parse_args()
    if a.status:
        print_status(); return

    procs = []
    def spawn(name, cmd, logname):
        log = open(os.path.join(HERE, logname), "a", encoding="utf-8")
        p = subprocess.Popen([PY] + cmd, cwd=HERE, stdout=log, stderr=subprocess.STDOUT)
        procs.append((name, p, log)); print(f"[launch] {name} pid={p.pid} -> {logname}")

    try:
        import torch  # noqa
        gpu_ok = torch.cuda.is_available()
    except Exception:
        gpu_ok = False

    if a.only != "cpu":
        if gpu_ok:
            spawn("gpu", ["gpu_search.py", "--pop", "8192"], "gpu_faed.log")
        else:
            print("[launch] GPU/torch indisponivel — pulando motor gpu")
    if a.only != "gpu":
        spawn("cpu", ["runner.py"], "runner.log")

    if not procs:
        print("[launch] nada para rodar"); return
    print("[launch] rodando. Ctrl-C para parar. Status: python launch.py --status")

    def stop(*_):
        print("\n[launch] parando motores...")
        for name, p, log in procs:
            try: p.terminate()
            except Exception: pass
        for name, p, log in procs:
            try: p.wait(timeout=8)
            except Exception: p.kill()
            log.close()
        sys.exit(0)
    signal.signal(signal.SIGINT, stop)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, stop)

    while True:
        time.sleep(10)
        if solved():
            print("\n*** UM ORACULO FECHOU — ver solver/out/SOLVED.json ***")
            print_status(); stop()
        alive = [name for name, p, _ in procs if p.poll() is None]
        if not alive:
            print("[launch] todos os motores encerraram."); print_status(); return

if __name__ == "__main__":
    main()
