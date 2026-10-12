import numpy as np
from scipy.special import comb

def exact_success_prob(p, key_size=256, N=15):
    t = N // 2
    p_block = sum(comb(N, i) * (p**i) * ((1-p)**(N-i)) for i in range(t + 1))
    return (p_block ** key_size) * 100

for p in [0.01, 0.05, 0.10, 0.12, 0.15, 0.20]:
    print(f"p={p}: {exact_success_prob(p, 256, 31):.2f}% (N=31)")
    print(f"p={p}: {exact_success_prob(p, 256, 47):.2f}% (N=47)")
    print(f"p={p}: {exact_success_prob(p, 256, 63):.2f}% (N=63)")

