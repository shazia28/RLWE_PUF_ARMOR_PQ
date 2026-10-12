import numpy as np
from scipy.special import comb

def exact_success_prob(p, key_size=256, N=15):
    t = N // 2
    p_block = sum(comb(N, i) * (p**i) * ((1-p)**(N-i)) for i in range(t + 1))
    return (p_block ** key_size) * 100

for p in [0.05, 0.08, 0.10, 0.12, 0.15, 0.18, 0.20]:
    print(f"p={p}: {exact_success_prob(p, 256, 7):.2f}% (N=7)")
    print(f"p={p}: {exact_success_prob(p, 256, 9):.2f}% (N=9)")
    print(f"p={p}: {exact_success_prob(p, 256, 11):.2f}% (N=11)")
    print(f"p={p}: {exact_success_prob(p, 256, 15):.2f}% (N=15)")
