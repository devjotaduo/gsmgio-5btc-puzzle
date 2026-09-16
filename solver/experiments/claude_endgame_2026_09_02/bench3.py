import sys,os,time,itertools
sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
import numpy as np, gsmg_common as G
exec(open("bifid3x3_exhaustive.py").read().split("# ------------------------------------------------------------------ estatisticas")[0].replace('open(LOG, "w").close()','pass').replace('log({"kind": "hypothesis", "text": __doc__.strip()})',''))
t0=time.time()
t=sym2arr(G.FAED); ir,ic,cls=bifid_index(570,30,"decrypt")
out=bifid_all(t,CLASSES[:15120],ir,ic); print("bifid_all 15120:",round(time.time()-t0,2))
t0=time.time()
K=out.shape[0]; o=out.reshape(K,-1).astype(np.int64)
codes=o[:,:-1]*9+o[:,1:]+81*np.arange(K)[:,None]
N=np.bincount(codes.ravel(),minlength=81*K).reshape(K,9,9).astype(np.float64)
print("digraph 15120:",round(time.time()-t0,2))
t0=time.time()
sh=out[:250][:,np.stack([np.random.permutation(570) for _ in range(200)])]
print("shuffle gather:",sh.shape,round(time.time()-t0,2))
t0=time.time()
K2=250*200; o2=sh.reshape(K2,-1).astype(np.int64)
c2=o2[:,:-1]*9+o2[:,1:]+81*np.arange(K2)[:,None]
N2=np.bincount(c2.ravel(),minlength=81*K2)
print("digraph 50000:",round(time.time()-t0,2))
print("mem ok")
