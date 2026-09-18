# -*- coding: utf-8 -*-
"""Chama o Codex CLI (`codex exec`) com limites fixos, para o Claude trabalhar em dupla com ele.

Contrato (ver AGENTS.md, "Trabalho em dupla"):
- sandbox read-only e approval_policy=never por padrão; `--write` exige `--cwd` da frente;
- prompt pelo stdin; no Windows chama `node codex.js` direto (o shim .cmd passa pelo cmd.exe);
- resposta final validada contra o JSON Schema; eventos e stderr vão direto para arquivo;
- timeout encerra a árvore de processos; meta.json é gravado em qualquer saída;
- retomada só por UUID, com trava por thread; pasta de saída exclusiva por execução.

Uso:
  python tools/codex_pair.py --prompt-file p.txt [--schema s.json] [--resume <uuid>]
                             [--write --cwd <dir da frente> [--add-dir <dir>]...]
  python tools/codex_pair.py --selftest
"""
import argparse, json, os, re, shutil, subprocess, sys, time, uuid
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAIR = os.path.join(ROOT, "_work", "codex_pair")  # fora do git: só *.md de _work entra
# travas junto do armazenamento de sessões do Codex: valem para todas as worktrees
LOCKS = os.path.join(os.environ.get("CODEX_HOME") or os.path.join(os.path.expanduser("~"), ".codex"),
                     "tmp", "codex_pair_locks")
MODEL, EFFORT = "gpt-6-astra", "max"
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def codex_argv():
    if os.name != "nt":
        exe = shutil.which("codex")
        return [exe] if exe else None
    # codex.cmd passa pelo cmd.exe, que interpreta & | < > ^ % nos argumentos; node + codex.js não.
    shim, node = shutil.which("codex.cmd"), shutil.which("node")
    if not (shim and node):
        return None
    js = os.path.join(os.path.dirname(shim), "node_modules", "@openai", "codex", "bin", "codex.js")
    return [node, js] if os.path.exists(js) else None


def build_cmd(codex, cwd, out_file, model, effort, sandbox, schema=None, resume=None,
              user_config=False, add_dirs=()):
    # -C/-s/--color/--add-dir só existem no nível `exec`. As sobrescritas -c vão DEPOIS de
    # `resume <id>`: antes dele a retomada as ignora e volta ao sandbox padrão (verificado na 0.155.0).
    cmd = [*codex, "exec", "-C", cwd, "-s", sandbox, "--color", "never"]
    for d in add_dirs:
        cmd += ["--add-dir", d]
    if resume:
        cmd += ["resume", resume]
    cmd += ["-c", 'approval_policy="never"', "-c", f'sandbox_mode="{sandbox}"']
    if os.name == "nt":
        # sem isto o sandbox padrão do Windows rejeita todo comando ("blocked by policy") quando a
        # config global (que traz [windows] sandbox="elevated") é ignorada: o Codex não lê arquivo algum.
        cmd += ["-c", 'windows.sandbox="elevated"']
    cmd += ["-m", model, "-c", f'model_reasoning_effort="{effort}"', "--json", "-o", out_file]
    if schema:
        cmd += ["--output-schema", schema]
    if not user_config:
        cmd.append("--ignore-user-config")  # sem MCPs/credenciais globais alheios ao GSMG
    return cmd + ["-"]


def thread_id(events_text):
    for line in events_text.splitlines():
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if isinstance(ev, dict) and ev.get("type") == "thread.started":
            return ev.get("thread_id")
    return None


def kill_tree(p):
    """Devolve None se a árvore morreu; senão, a descrição da falha (nunca afirma o que não verificou)."""
    if os.name == "nt":
        tk = subprocess.run(["taskkill", "/T", "/F", "/PID", str(p.pid)], capture_output=True)
        if tk.returncode != 0 and p.poll() is None:
            return f"taskkill rc={tk.returncode}"
    else:
        p.kill()
    try:
        p.wait(timeout=30)
        return None
    except subprocess.TimeoutExpired:
        return "processo não terminou 30 s após o encerramento"


def execute(cmd, prompt, ev_path, err_path, timeout):
    """stdout/stderr vão direto para arquivo: nenhum pipe fica preso ao processo neto (node → codex)."""
    with open(ev_path, "wb") as ev, open(err_path, "wb") as er:
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=ev, stderr=er)
        try:
            p.communicate(prompt.encode("utf-8"), timeout=timeout)
            return p.returncode, None
        except subprocess.TimeoutExpired:
            falha = kill_tree(p)
            if falha:
                return p.returncode, f"timeout de {timeout}s; FALHA ao encerrar a árvore: {falha}"
            return p.returncode, f"timeout de {timeout}s: árvore de processos encerrada"


def check_response(resp, schema, rc):
    if rc != 0:
        return f"codex saiu com código {rc} (ver stderr.txt)"
    if not os.path.exists(resp):
        return "codex não gravou a resposta final"
    if schema:
        import jsonschema
        try:
            jsonschema.validate(json.load(open(resp, encoding="utf-8")), json.load(open(schema, encoding="utf-8")))
        except (ValueError, jsonschema.ValidationError) as e:
            return f"resposta fora do schema: {str(e)[:500]}"
    return None


def git(cwd, *args):
    return subprocess.run(["git", "-C", cwd, *args], capture_output=True, text=True).stdout.strip()


def run(a):
    codex = codex_argv()
    if not codex:
        sys.exit("codex CLI não encontrado (no Windows: node + node_modules/@openai/codex/bin/codex.js)")
    if a.resume and not UUID_RE.match(a.resume):
        sys.exit("--resume exige o UUID do thread_id (nunca nome de sessão nem --last)")
    if a.write and not a.cwd:
        sys.exit("--write exige --cwd com o diretório da frente ou a worktree do Codex")
    lock = None
    if a.resume:
        lock = os.path.join(LOCKS, a.resume + ".lock")
        os.makedirs(os.path.dirname(lock), exist_ok=True)
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            sys.exit(f"thread {a.resume} em uso por outra chamada ({lock}); serialize ou apague a trava órfã")
        os.write(fd, str(os.getpid()).encode())
        os.close(fd)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = a.out or os.path.join(PAIR, f"{stamp}_{uuid.uuid4().hex[:8]}")
    meta, t0, criada = {"ok": False, "erro": None, "rc": None, "resume_de": a.resume}, time.time(), False
    try:
        os.makedirs(out)  # exclusiva: nunca reaproveita resposta de outra execução
        criada = True
        prompt = open(a.prompt_file, encoding="utf-8").read()
        open(os.path.join(out, "prompt.txt"), "w", encoding="utf-8").write(prompt)
        resp = os.path.join(out, "response.json" if a.schema else "response.txt")
        cwd = os.path.abspath(a.cwd or ROOT)
        cmd = build_cmd(codex, cwd, resp, a.model, a.effort,
                        "workspace-write" if a.write else "read-only", a.schema, a.resume,
                        a.user_config, [os.path.abspath(d) for d in a.add_dir])
        meta.update(cmd=cmd, resposta=resp, model=a.model, effort=a.effort, sandbox=cmd[cmd.index("-s") + 1],
                    cwd=cwd, git_head=git(cwd, "rev-parse", "HEAD"), git_sujo=bool(git(cwd, "status", "--porcelain")),
                    wrapper_head=git(ROOT, "rev-parse", "HEAD"))
        meta["rc"], meta["erro"] = execute(cmd, prompt, os.path.join(out, "events.jsonl"),
                                           os.path.join(out, "stderr.txt"), a.timeout)
        meta["erro"] = meta["erro"] or check_response(resp, a.schema, meta["rc"])
        meta["ok"] = meta["erro"] is None
    except Exception as e:
        meta["erro"] = meta["erro"] or f"{type(e).__name__}: {e}"
        raise
    finally:
        meta["secs"] = round(time.time() - t0, 1)
        ev = os.path.join(out, "events.jsonl")
        meta["thread_id"] = (thread_id(open(ev, encoding="utf-8", errors="replace").read())
                             if criada and os.path.exists(ev) else None)
        if criada:  # nunca escreve na pasta de outra execução
            json.dump(meta, open(os.path.join(out, "meta.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        if lock:
            os.remove(lock)
        print(json.dumps({k: meta.get(k) for k in ("ok", "rc", "secs", "thread_id", "resposta", "erro")},
                         ensure_ascii=False))
    return 0 if meta["ok"] else 1


def selftest():
    import tempfile
    c = build_cmd(["codex"], ROOT, "o.json", "m", "high", "read-only", schema="s.json", add_dirs=["d"])
    assert c[:5] == ["codex", "exec", "-C", ROOT, "-s"] and c[5] == "read-only" and c[-1] == "-", c
    assert "--ignore-user-config" in c and c[c.index("--output-schema") + 1] == "s.json", c
    assert os.name != "nt" or 'windows.sandbox="elevated"' in c, c
    r = build_cmd(["codex"], ROOT, "o.txt", "m", "high", "read-only", resume="abc", user_config=True, add_dirs=["d"])
    i = r.index("resume")
    assert r[i + 1] == "abc" and r.index("-s") < r.index("--add-dir") < i < r.index("-m"), r
    assert i < r.index('approval_policy="never"') and i < r.index('sandbox_mode="read-only"'), r
    assert os.name != "nt" or i < r.index('windows.sandbox="elevated"'), r
    assert "--ignore-user-config" not in r, r
    assert UUID_RE.match("01a0b32c-def6-7150-b592-32a0d997496c") and not UUID_RE.match("--last")
    ev = '{"type":"turn.started"}\n{truncado\nnão-json\n{"type":"thread.started","thread_id":"01a0-xyz"}\n'
    assert thread_id(ev) == "01a0-xyz" and thread_id('{"type":"turn.started"}') is None
    with tempfile.TemporaryDirectory() as t:
        sch, resp = os.path.join(t, "s.json"), os.path.join(t, "r.json")
        json.dump({"type": "object", "required": ["veredito"]}, open(sch, "w"))
        json.dump({"outro": 1}, open(resp, "w"))
        assert "fora do schema" in check_response(resp, sch, 0)
        json.dump({"veredito": "ok"}, open(resp, "w"))
        assert check_response(resp, sch, 0) is None and "código 2" in check_response(resp, sch, 2)
        assert "não gravou" in check_response(os.path.join(t, "nada.json"), sch, 0)
        # timeout: o filho lança um neto que gravaria o marcador após 3 s; a árvore inteira tem de morrer
        marker = os.path.join(t, "neto_vivo.txt")
        neto = "import sys,time,pathlib; time.sleep(3); pathlib.Path(sys.argv[1]).write_text('vivo')"
        filho = f"import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',{neto!r},sys.argv[1]]); time.sleep(30)"
        t0 = time.time()
        rc, erro = execute([sys.executable, "-c", filho, marker], "", os.path.join(t, "e"), os.path.join(t, "x"), 1)
        assert erro and "timeout" in erro and time.time() - t0 < 10, (rc, erro, time.time() - t0)
        time.sleep(4)
        assert not os.path.exists(marker), "neto sobreviveu ao timeout"
    with tempfile.TemporaryDirectory() as t:
        prev = os.path.join(t, "meta.json"); open(prev, "w").write("anterior")
        pf = os.path.join(t, "p.txt"); open(pf, "w").write("x")
        ns = argparse.Namespace(resume=None, write=False, cwd=None, out=t, prompt_file=pf, schema=None, model="m",
                                effort="low", user_config=False, add_dir=[], timeout=5)
        try:
            run(ns)
            raise AssertionError("--out existente deveria falhar")
        except FileExistsError:
            pass
        assert open(prev).read() == "anterior", "meta.json da execução anterior foi sobrescrito"
    print("codex_pair selftest OK")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--prompt-file")
    ap.add_argument("--schema", help="JSON Schema da resposta final (--output-schema + validação local)")
    ap.add_argument("--resume", metavar="UUID", help="retoma a sessão pelo thread_id (nunca --last)")
    ap.add_argument("--write", action="store_true", help="workspace-write; exige --cwd da frente")
    ap.add_argument("--cwd", help="diretório de trabalho do Codex (padrão: raiz desta worktree)")
    ap.add_argument("--add-dir", action="append", default=[], help="diretório gravável extra (com --write)")
    ap.add_argument("--user-config", action="store_true",
                    help="carrega ~/.codex/config.toml (MCPs globais, web_search, trust); o padrão isola o GSMG")
    ap.add_argument("--model", default=MODEL)
    ap.add_argument("--effort", default=EFFORT)
    ap.add_argument("--out", help="pasta de saída NOVA (padrão _work/codex_pair/<carimbo>_<uuid>)")
    ap.add_argument("--timeout", type=int, default=3600)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest()
        sys.exit(0)
    if not a.prompt_file:
        ap.error("--prompt-file é obrigatório")
    sys.exit(run(a))
