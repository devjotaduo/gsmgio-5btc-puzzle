# -*- coding: utf-8 -*-
"""Host pyopencl: compila o kernel, roda o modo debug (Controle A) e o scan.
Referência AES via pycryptodome/G para comparação byte a byte."""
import os
import numpy as np
import pyopencl as cl
from Crypto.Cipher import AES

import refkit as R
G = R.G

HERE = os.path.dirname(os.path.abspath(__file__))


def _select_device():
    for p in cl.get_platforms():
        if "NVIDIA" in p.name.upper():
            return p.get_devices()[0]
    return cl.get_platforms()[0].get_devices()[0]


class GPU:
    def __init__(self, device=None):
        self.dev = device or _select_device()
        self.ctx = cl.Context([self.dev])
        self.queue = cl.CommandQueue(self.ctx,
                                     properties=cl.command_queue_properties.PROFILING_ENABLE)
        src = open(os.path.join(HERE, "kernel.cl"), "r", encoding="utf-8").read()
        tti = ",".join(str(x) for x in R.token_type_index())
        src = src.replace("TTI_VALUES", tti)
        self.prog = cl.Program(self.ctx, src).build()
        self.k_scan = cl.Kernel(self.prog, "k_scan")
        self.k_debug = cl.Kernel(self.prog, "k_debug")
        self.mf = cl.mem_flags

    def _bufs(self, salt, ct):
        mf = self.mf
        salt = bytes(salt); ct = bytes(ct)
        assert len(salt) == 8 and len(ct) == 80
        salt_b = cl.Buffer(self.ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=np.frombuffer(salt, np.uint8))
        ct_b = cl.Buffer(self.ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=np.frombuffer(ct, np.uint8))
        return salt_b, ct_b

    def debug_run(self, indices, salt, ct):
        """Devolve dict por índice: key,iv,P0,P3,P4 (bytes) calculados na GPU."""
        idx = np.asarray(indices, dtype=np.uint64)
        n = idx.size
        mf = self.mf
        salt_b, ct_b = self._bufs(salt, ct)
        idx_b = cl.Buffer(self.ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=idx)
        out = np.zeros(n * 96, dtype=np.uint8)
        out_b = cl.Buffer(self.ctx, mf.WRITE_ONLY, out.nbytes)
        self.k_debug(self.queue, (int(n),), None, idx_b, np.uint32(n),
                     salt_b, ct_b, out_b)
        cl.enqueue_copy(self.queue, out, out_b); self.queue.finish()
        res = []
        for i in range(n):
            o = out[i * 96:(i + 1) * 96].tobytes()
            res.append({"key": o[0:32], "iv": o[32:48],
                        "P0": o[48:64], "P3": o[64:80], "P4": o[80:96]})
        return res

    def scan_batch(self, base, count, salt, ct, cap=65536, local=64):
        """Roda k_scan em [base, base+count). Retorna (survivors_list, total_count, overflow)."""
        mf = self.mf
        salt_b, ct_b = self._bufs(salt, ct)
        out_idx = cl.Buffer(self.ctx, mf.WRITE_ONLY, cap * 8)
        cnt = np.zeros(1, np.uint32)
        ovf = np.zeros(1, np.int32)
        cnt_b = cl.Buffer(self.ctx, mf.READ_WRITE | mf.COPY_HOST_PTR, hostbuf=cnt)
        ovf_b = cl.Buffer(self.ctx, mf.READ_WRITE | mf.COPY_HOST_PTR, hostbuf=ovf)
        gsize = int(((count + local - 1) // local) * local)
        self.k_scan(self.queue, (gsize,), (local,),
                    np.uint64(base), np.uint64(count), salt_b, ct_b,
                    out_idx, cnt_b, np.uint32(cap), ovf_b)
        cl.enqueue_copy(self.queue, cnt, cnt_b)
        cl.enqueue_copy(self.queue, ovf, ovf_b)
        self.queue.finish()
        total = int(cnt[0]); overflow = bool(ovf[0])
        got = min(total, cap)
        survivors = []
        if got:
            arr = np.zeros(cap, np.uint64)
            cl.enqueue_copy(self.queue, arr, out_idx); self.queue.finish()
            survivors = [int(x) for x in arr[:got]]
        return survivors, total, overflow

    def time_scan(self, base, count, salt, ct, local=64):
        """Enfileira k_scan e devolve o tempo de kernel (s) via profiling do device."""
        mf = self.mf
        salt_b, ct_b = self._bufs(salt, ct)
        out_idx = cl.Buffer(self.ctx, mf.WRITE_ONLY, 65536 * 8)
        cnt = np.zeros(1, np.uint32); ovf = np.zeros(1, np.int32)
        cnt_b = cl.Buffer(self.ctx, mf.READ_WRITE | mf.COPY_HOST_PTR, hostbuf=cnt)
        ovf_b = cl.Buffer(self.ctx, mf.READ_WRITE | mf.COPY_HOST_PTR, hostbuf=ovf)
        gsize = int(((count + local - 1) // local) * local)
        ev = self.k_scan(self.queue, (gsize,), (local,),
                         np.uint64(base), np.uint64(count), salt_b, ct_b,
                         out_idx, cnt_b, np.uint32(65536), ovf_b)
        ev.wait()
        return (ev.profile.end - ev.profile.start) * 1e-9


# --------------------------------------------------- referência AES em CPU
def cpu_keyiv(index, salt):
    pw = R.password_for_index(index)
    return G.evp(pw, bytes(salt), G.SHA256)  # (key32, iv16)


def cpu_blocks(index, salt, ct):
    """P0,P3,P4 via pycryptodome, mesmo esquema do kernel."""
    pw = R.password_for_index(index)
    key, iv = G.evp(pw, bytes(salt), G.SHA256)
    dec = AES.new(key, AES.MODE_CBC, iv).decrypt(bytes(ct))
    return key, iv, dec[0:16], dec[48:64], dec[64:80]
