import pickle, numpy as np, random, time, os
SP = os.path.dirname(os.path.abspath(__file__))
tab, floor, held = pickle.load(open(os.path.join(SP,"quad_nl.pkl"),"rb"))
T = np.asarray(tab, dtype=np.float32)
W = np.array([17576,676,26,1], dtype=np.int64)
rng = random.Random(0)
for n in (500, 285):
    seq = [rng.randrange(25) for _ in range(n)]
    S = np.asarray(seq); Q = np.stack([S[0:n-3],S[1:n-2],S[2:n-1],S[3:n]],axis=1)
    QW = Q  # gather
    ka = np.arange(26)
    t0=time.time()
    for _ in range(5000):
        s = float(T[(ka[Q]*W).sum(1)].sum())
    print(n, "5000 evals", round(time.time()-t0,2), "s")
