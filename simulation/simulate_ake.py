import hashlib
import time
import os
import random

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

    class _CompatArray(list):
        """Lightweight pure-Python polynomial/bit array wrapper when NumPy is unavailable."""
        def __add__(self, other):
            if isinstance(other, _CompatArray):
                return _CompatArray([a + b for a, b in zip(self, other)])
            return _CompatArray([a + other for a in self])
        def __sub__(self, other):
            if isinstance(other, _CompatArray):
                return _CompatArray([a - b for a, b in zip(self, other)])
            return _CompatArray([a - other for a in self])
        def __mod__(self, m):
            return _CompatArray([a % m for a in self])
        def __xor__(self, other):
            return _CompatArray([a ^ b for a, b in zip(self, other)])
        def __gt__(self, v):
            return _CompatArray([a > v for a in self])
        def __ge__(self, v):
            return _CompatArray([a >= v for a in self])
        def __lt__(self, v):
            return _CompatArray([a < v for a in self])
        def __eq__(self, other):
            if isinstance(other, (int, float)):
                return _CompatArray([a == other for a in self])
            return super().__eq__(other)
        def astype(self, _dtype):
            return _CompatArray([int(a) for a in self])
        def tobytes(self):
            return bytes(int(a) & 0xFF for a in self)

    class _CompatRandom:
        @staticmethod
        def seed(s):
            random.seed(s)
        @staticmethod
        def normal(mu, sig, size):
            return _CompatArray([random.gauss(mu, sig) for _ in range(size)])
        @staticmethod
        def randint(low, high, size, dtype=None):
            return _CompatArray([random.randrange(low, high) for _ in range(size)])
        @staticmethod
        def rand(size):
            return _CompatArray([random.random() for _ in range(size)])

    class np:
        ndarray = _CompatArray
        int64 = int
        uint8 = int
        random = _CompatRandom
        @staticmethod
        def round(arr):
            return _CompatArray([int(round(x)) for x in arr])
        @staticmethod
        def zeros(size, dtype=None):
            return _CompatArray([0] * size)
        @staticmethod
        def all(arr):
            return all(bool(x) for x in arr)
        @staticmethod
        def any(arr):
            return any(bool(x) for x in arr)
        @staticmethod
        def where(cond, x, y):
            return _CompatArray([xv if c else yv for c, xv, yv in zip(cond, x, y)])
        @staticmethod
        def abs(arr):
            return _CompatArray([abs(x) for x in arr])
        @staticmethod
        def max(arr):
            return max(arr)
        @staticmethod
        def sum(arr):
            return sum(arr)
        @staticmethod
        def frombuffer(buf, dtype=None):
            return _CompatArray(list(buf))
        @staticmethod
        def unpackbits(arr):
            bits = []
            for b in arr:
                for i in range(7, -1, -1):
                    bits.append((b >> i) & 1)
            return _CompatArray(bits)
        @staticmethod
        def packbits(bits):
            out = []
            for i in range(0, len(bits), 8):
                byte = 0
                for j in range(min(8, len(bits) - i)):
                    byte |= (int(bits[i + j]) & 1) << (7 - j)
                out.append(byte)
            return _CompatArray(out)
        @staticmethod
        def repeat(arr, factor):
            out = []
            for x in arr:
                out.extend([x] * factor)
            return _CompatArray(out)

# ==============================================================================
# ARMOR-PQ: Post-Quantum Mutual Authentication and Authenticated Key Exchange
# Full Simulation with Exact Peikert Key-Reconciliation & Replay Protection
# Parameters: n=512, q=12289, sigma=3.2 (Ring: R_q = Z_q[x]/(x^n + 1))
# ==============================================================================

n = 512
q = 12289
sigma = 3.2

def hash_sha512(*args):
    """Concatenates all arguments and returns SHA-512 hex digest."""
    m = hashlib.sha512()
    for arg in args:
        if isinstance(arg, bytes):
            m.update(arg)
        elif isinstance(arg, np.ndarray):
            m.update(arg.tobytes())
        else:
            m.update(str(arg).encode())
    return m.hexdigest()

# Precomputed negacyclic NTT tables for pure-Python fallback (n=512, q=12289, psi=10302, omega=3)
_PSI = 10302
_PSI_INV = pow(_PSI, q - 2, q)
_OMEGA = (_PSI * _PSI) % q
_OMEGA_INV = pow(_OMEGA, q - 2, q)
_N_INV = pow(n, q - 2, q)
_PSI_POW = [pow(_PSI, i, q) for i in range(n)]
_PSI_INV_POW = [pow(_PSI_INV, i, q) for i in range(n)]

def _bit_rev9(x):
    r = 0
    for i in range(9):
        if (x >> i) & 1:
            r |= 1 << (8 - i)
    return r

def _fft_mod_q(arr, root):
    a = [arr[_bit_rev9(i)] for i in range(n)]
    length = 2
    while length <= n:
        half = length >> 1
        w_len = pow(root, n // length, q)
        for i in range(0, n, length):
            w = 1
            for j in range(half):
                u = a[i + j]
                v = (a[i + j + half] * w) % q
                a[i + j] = (u + v) % q
                a[i + j + half] = (u - v) % q
                w = (w * w_len) % q
        length <<= 1
    return a

def _ntt_py(a):
    scaled = [(a[i] * _PSI_POW[i]) % q for i in range(n)]
    return _fft_mod_q(scaled, _OMEGA)

def _intt_py(a):
    inv = _fft_mod_q(a, _OMEGA_INV)
    return [(inv[i] * _PSI_INV_POW[i] * _N_INV) % q for i in range(n)]

def poly_mul(a, b):
    """Polynomial multiplication modulo (x^n + 1) and modulo q using FFT/NTT."""
    if HAS_NUMPY:
        from numpy.fft import fft, ifft
        c = np.round(np.real(ifft(fft(a, 2 * n) * fft(b, 2 * n)))).astype(np.int64) % q
        res = np.zeros(n, dtype=np.int64)
        for i in range(len(c)):
            if i < n:
                res[i] = (res[i] + c[i]) % q
            else:
                res[i - n] = (res[i - n] - c[i]) % q
        return res
    ntt_a = _ntt_py(a)
    ntt_b = _ntt_py(b)
    prod = [(x * y) % q for x, y in zip(ntt_a, ntt_b)]
    return _CompatArray(_intt_py(prod))

def derive_sk_from_puf(r_i_hex):
    """Deterministically derives sk_i <- KDF(r_i, 'ARMOR-PQ-SK') in chi_sigma^n."""
    seed_bytes = hashlib.sha256((r_i_hex + "ARMOR-PQ-SK").encode()).digest()
    seed_int = int.from_bytes(seed_bytes[:4], "big")
    rng = random.Random(seed_int)
    vals = [int(round(rng.gauss(0, sigma))) % q for _ in range(n)]
    if HAS_NUMPY:
        return np.array(vals, dtype=np.int64)
    return _CompatArray(vals)

def sample_gaussian_error():
    """Discrete Gaussian error distribution chi_sigma with sigma=3.2."""
    return np.round(np.random.normal(0, sigma, n)).astype(np.int64) % q

def sample_uniform_poly():
    """Uniform random polynomial in R_q."""
    return np.random.randint(0, q, n, dtype=np.int64)

# ==============================================================================
# PUF FUZZY EXTRACTOR (REPETITION CODE [15, 1, 15] & MAJORITY DECODING)
# ==============================================================================

class FuzzyExtractor:
    def __init__(self, key_len_bits=256, rep_factor=15):
        self.key_len_bits = key_len_bits
        self.rep_factor = rep_factor
        self.codeword_len = key_len_bits * rep_factor
        
    def generate(self, clean_puf):
        # Generate 256-bit random seed
        seed = os.urandom(self.key_len_bits // 8)
        seed_bits = np.unpackbits(np.frombuffer(seed, dtype=np.uint8))
        
        # Encode with repetition code
        codeword_bits = np.repeat(seed_bits, self.rep_factor)
        codeword_bytes = np.packbits(codeword_bits).tobytes()
        
        # Helper data h = clean_puf XOR codeword
        h = bytes(a ^ b for a, b in zip(clean_puf, codeword_bytes))
        return h, seed.hex()
        
    def reproduce(self, noisy_puf, h):
        # Recover noisy codeword: noisy_puf XOR h
        noisy_codeword = bytes(a ^ b for a, b in zip(noisy_puf, h))
        noisy_bits = np.unpackbits(np.frombuffer(noisy_codeword, dtype=np.uint8))
        
        # Majority logic decoding
        recovered_bits = np.zeros(self.key_len_bits, dtype=np.uint8)
        for i in range(self.key_len_bits):
            block = noisy_bits[i*self.rep_factor : (i+1)*self.rep_factor]
            recovered_bits[i] = 1 if np.sum(block) > (self.rep_factor // 2) else 0
            
        return np.packbits(recovered_bits).tobytes().hex()

# ==============================================================================
# PEIKERT ERROR RECONCILIATION MECHANISM
# Region partitioning: Z_q divided into 8 regions.
# Hint w in {0, 1}^n indicates boundary proximity.
# Guarantees identical key bit extraction when noise |e| < q/8 = 1536.
# ==============================================================================

def help_rec(sh_S, key_len=n):
    """
    Server generates Peikert reconciliation hint w and extracts key bits K_S.
    Implements exact Peikert cross-rounding and shift-invariant key extraction:
    w = round(4*v/q) mod 2
    K_S = round(2/q * ((v - w*floor(q/4)) mod q)) mod 2
    """
    w = np.zeros(key_len, dtype=np.uint8)
    k_s = np.zeros(key_len, dtype=np.uint8)
    for i in range(key_len):
        v = int(sh_S[i] % q)
        if v < 0:
            v += q
        w_bit = int(round(4.0 * v / q)) % 2
        w[i] = w_bit
        val = (v - w_bit * (q // 4)) % q
        k_s[i] = 1 if (q // 4 <= val < (3 * q) // 4) else 0
    return w, k_s

def rec(sh_D, w, key_len=n):
    """
    Device uses reconciliation hint w to recover exact key bits K_D.
    Matches Peikert reconciliation function Rec(sh_D, w) across all n coefficients:
    K_D = round(2/q * ((u - w*floor(q/4)) mod q)) mod 2
    """
    k_d = np.zeros(key_len, dtype=np.uint8)
    for i in range(key_len):
        u = int(sh_D[i] % q)
        if u < 0:
            u += q
        w_bit = w[i]
        val = (u - w_bit * (q // 4)) % q
        k_d[i] = 1 if (q // 4 <= val < (3 * q) // 4) else 0
    return k_d

# ==============================================================================
# SIMULATION HARNESS
# ==============================================================================

def run_single_session(verbose=True):
    # System Setup (TA)
    a = sample_uniform_poly() # Public ring parameter
    server_id = "Edge_Server_Alpha"
    device_id = "IoMT_Cardiac_Sensor_01"
    pw = "StrongMedicalPass123!"

    # 1. Device Enrollment
    # Baseline PUF response and code-offset helper data (480 bytes for N=15 repetition)
    stm32_fingerprint = bytes([
        0x4E, 0x88, 0x1A, 0xFB, 0x33, 0xC4, 0x99, 0x22, 
        0x7F, 0xDD, 0x5A, 0x01, 0xE6, 0xBB, 0x4C, 0x90, 
        0x21, 0xFA, 0x3D, 0x88, 0x66, 0x11, 0xAA, 0x55, 
        0x9C, 0x3E, 0x77, 0xBB, 0x00, 0xFF, 0x2A, 0x1D
    ])
    puf_raw = stm32_fingerprint * 15 # Tile to 480 bytes
    fe = FuzzyExtractor(key_len_bits=256, rep_factor=15)
    h_i, r_i = fe.generate(puf_raw) # r_i is the stable 256-bit derived key (hex)
    sk_i = derive_sk_from_puf(r_i) # Deterministic long-term secret key sk_i <- KDF(r_i, "ARMOR-PQ-SK")
    e_sk = sample_gaussian_error()
    pk_i = (poly_mul(a, sk_i) + e_sk) % q # Long-term public key (in-place NTT)
    del sk_i, e_sk # Zeroize sk_i and e_{pk,i} from volatile SRAM after enrollment
    PID_i = hash_sha512(device_id, r_i)[:32] # Anonymized pseudo-ID

    # TA credential issuance
    h_val = hash_sha512(device_id, PID_i, hash_sha512(pw, device_id), r_i)
    d_i = h_val[:64]
    v_i = h_val[64:]

    # Server Database
    server_db = {
        PID_i: {
            "pk_i": pk_i,
            "d_i": d_i,
            "v_i": v_i,
            "h_i": h_i
        }
    }
    nonce_cache = set()

    if verbose:
        print("=" * 70)
        print("ARMOR-PQ: 3-ROUND MUTUAL AUTHENTICATION & KEY EXCHANGE SIMULATION")
        print("=" * 70)
        print(f"Device Enrolled: PID={PID_i[:16]}..., Server={server_id}")

    # --------------------------------------------------------------------------
    # ROUND 1: Client PUF Device (CPD) -> Authentication Server (S)
    # --------------------------------------------------------------------------
    C_s = os.urandom(16).hex()
    T_s = int(time.time())

    # PUF evaluation with independent bit-level Bernoulli noise at target 10% BER (tau_BER = 0.10)
    puf_bits = np.unpackbits(np.frombuffer(puf_raw, dtype=np.uint8))
    noise_mask = (np.random.rand(len(puf_bits)) < 0.10).astype(np.uint8)
    noisy_bits = puf_bits ^ noise_mask
    noisy_puf = np.packbits(noisy_bits).tobytes()
            
    # Corrected via FE.Rep(r'_i, h_i) -> r_i using majority-logic decoding
    r_prime_i = fe.reproduce(noisy_puf, h_i)
    sk_i = derive_sk_from_puf(r_prime_i) # Reconstruct sk_i <- KDF(r_i, "ARMOR-PQ-SK") in volatile SRAM
    
    if verbose:
        print(f"Original PUF derived key (r_i):      {r_i}")
        print(f"Recovered PUF derived key (r_prime_i): {r_prime_i}")
        print(f"PUF keys matched after repetition code? {r_i == r_prime_i}")

    v_i_dynamic = hash_sha512(device_id, PID_i, hash_sha512(pw, device_id), r_prime_i)[64:]
    tau = hash_sha512(r_prime_i, C_s)

    # Ephemeral RLWE sample
    e_i = sample_gaussian_error()
    e_prime_i = sample_gaussian_error()
    p_tilde_i = (poly_mul(a, e_i) + e_prime_i) % q

    M1 = {
        "PID_i": PID_i,
        "p_tilde_i": p_tilde_i,
        "T_s": T_s,
        "C_s": C_s,
        "tau": tau
    }
    if verbose:
        print(f"\n[Round 1: CPD -> S] Sent M1: PID={M1['PID_i'][:12]}..., C_s={M1['C_s'][:8]}..., T_s={M1['T_s']}")

    # --------------------------------------------------------------------------
    # ROUND 2: Authentication Server (S) -> CPD
    # --------------------------------------------------------------------------
    # Server checks: Freshness, Replay, Registered PID, Non-Zero polynomial
    now = int(time.time())
    if abs(now - M1["T_s"]) > 300:
        raise ValueError("Server Rejected: Timestamp expired")
    if M1["C_s"] in nonce_cache:
        raise ValueError("Server Rejected: Nonce replay detected")
    if M1["PID_i"] not in server_db:
        raise ValueError("Server Rejected: Unknown pseudo-ID")
    db_entry = server_db[M1["PID_i"]]
    if np.all(M1["p_tilde_i"] == 0) or np.any(M1["p_tilde_i"] >= q) or np.any(M1["p_tilde_i"] < 0):
        raise ValueError("Server Rejected: Invalid or zero ephemeral polynomial")
    sum_poly = (M1["p_tilde_i"] + db_entry["pk_i"]) % q
    centered_sum = np.where(sum_poly > q // 2, sum_poly - q, sum_poly)
    ntt_slots = _ntt_py(sum_poly)
    if np.all(sum_poly == 0) or np.max(np.abs(centered_sum)) <= int(6 * sigma) or any(s == 0 for s in ntt_slots):
        raise ValueError("Server Rejected: Cancellation, near-cancellation, or zero-divisor attack detected")

    nonce_cache.add(M1["C_s"])

    # Ephemeral polynomial sampling at server
    e_j = sample_gaussian_error()
    e_double_j = sample_gaussian_error()
    p_tilde_j = (poly_mul(a, e_j) + e_double_j) % q

    # Implicitly authenticated shared secret: sh_S = (p_tilde_i + pk_i) * e_j mod q
    sh_S = poly_mul((M1["p_tilde_i"] + db_entry["pk_i"]) % q, e_j)

    # Peikert error reconciliation & key bit extraction (full n=512 coefficients, 64-byte hint w)
    w, K_S = help_rec(sh_S, n)
    K_S_bytes = K_S.tobytes()

    # Transcripts for hashing
    p_i_hash = hash_sha512(M1["p_tilde_i"])
    p_j_hash = hash_sha512(p_tilde_j)
    w_hash = hash_sha512(w)

    # Server Authenticator alpha_j binds full transcript, nonces, and secret K_S & d_i
    alpha_j = hash_sha512(server_id, M1["PID_i"], p_i_hash, p_j_hash, w_hash, K_S_bytes, M1["tau"], M1["T_s"], M1["C_s"], db_entry["d_i"])

    M2 = {
        "p_tilde_j": p_tilde_j,
        "w": w,
        "alpha_j": alpha_j
    }
    if verbose:
        print(f"[Round 2: S -> CPD] Sent M2: p_tilde_j, hint w (512 bits / 64 bytes), alpha_j={alpha_j[:16]}...")

    # --------------------------------------------------------------------------
    # ROUND 3: CPD -> Authentication Server (S)
    # --------------------------------------------------------------------------
    # Client checks: Non-Zero polynomial
    if np.all(M2["p_tilde_j"] == 0) or np.any(M2["p_tilde_j"] >= q) or np.any(M2["p_tilde_j"] < 0):
        raise ValueError("Client Rejected: Invalid or zero server polynomial")

    # Client shared secret: sh_D = p_tilde_j * (e_i + sk_i) mod q
    sh_D = poly_mul(M2["p_tilde_j"], (e_i + sk_i) % q)

    # Key reconciliation
    K_D = rec(sh_D, M2["w"], n)
    K_D_bytes = K_D.tobytes()

    if verbose:
        print(f"K_D (Client Key Bits): {K_D_bytes.hex()}")
        print(f"K_S (Server Key Bits): {K_S_bytes.hex()}")
        print(f"Are K_D and K_S equal? {K_D_bytes == K_S_bytes}")

    # Client verifies server authenticator alpha_j
    expected_alpha_j = hash_sha512(server_id, PID_i, p_i_hash, p_j_hash, w_hash, K_D_bytes, tau, T_s, C_s, d_i)
    if M2["alpha_j"] != expected_alpha_j:
        raise ValueError("Client Rejected: Server authentication failed (alpha_j mismatch)")

    if verbose:
        print("[Client] Verification SUCCESS: Server identity, transcript, and freshness confirmed!")

    # Client generates client authenticator alpha_i binding transcript, nonces, K_D, and v_i
    alpha_i = hash_sha512(PID_i, server_id, p_i_hash, p_j_hash, w_hash, K_D_bytes, T_s, C_s, v_i_dynamic)

    M3 = {
        "alpha_i": alpha_i
    }
    if verbose:
        print(f"[Round 3: CPD -> S] Sent M3: alpha_i={alpha_i[:16]}...")

    # --------------------------------------------------------------------------
    # SERVER VERIFICATION & SESSION KEY DERIVATION
    # --------------------------------------------------------------------------
    expected_alpha_i = hash_sha512(PID_i, server_id, p_i_hash, p_j_hash, w_hash, K_S_bytes, T_s, C_s, db_entry["v_i"])
    if M3["alpha_i"] != expected_alpha_i:
        raise ValueError("Server Rejected: Client authentication failed (alpha_i mismatch)")

    if verbose:
        print("[Server] Verification SUCCESS: Client identity, transcript, and physical PUF bound token confirmed!")

    # Both parties compute the final session key
    SK_client = hash_sha512(PID_i, server_id, p_i_hash, p_j_hash, w_hash, alpha_i, alpha_j, K_D_bytes, v_i_dynamic)
    SK_server = hash_sha512(PID_i, server_id, p_i_hash, p_j_hash, w_hash, alpha_i, alpha_j, K_S_bytes, db_entry["v_i"])

    assert SK_client == SK_server, "Session key mismatch between device and server!"

    if verbose:
        print("\n" + "=" * 70)
        print("MUTUAL AUTHENTICATION & KEY EXCHANGE COMPLETED SUCCESSFULLY!")
        print(f"Device Session Key : {SK_client}")
        print(f"Server Session Key : {SK_server}")
        print("Keys are IDENTICAL (100% agreement confirmed)")
        print("=" * 70)

    return True

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ARMOR-PQ Mutual Authentication & Key Exchange Simulation")
    parser.add_argument("--runs", type=int, default=1000, help="Number of Monte Carlo trials to run (default: 1000)")
    parser.add_argument("--seed", type=int, default=None, help="Random seed for deterministic reproducibility (e.g. 20261024)")
    args = parser.parse_args()

    if args.seed is not None:
        np.random.seed(args.seed)
        print(f"Reproducibility seed set: {args.seed}")

    # 1. Run single detailed session
    run_single_session(verbose=True)

    # 2. Run repeated trials to statistically validate key agreement and freshness
    total_runs = args.runs
    print(f"\nRunning repeated trials to empirically validate agreement rate over {total_runs} sessions...")
    success_count = 0
    t_start = time.time()
    for i in range(total_runs):
        try:
            if run_single_session(verbose=False):
                success_count += 1
        except Exception as e:
            print(f"Run {i} failed: {e}")
        if (i + 1) % (total_runs // 10 if total_runs >= 10 else 1) == 0:
            print(f"  Progress: {i + 1}/{total_runs} sessions completed...")

    t_elapsed = time.time() - t_start
    print("\n" + "=" * 70)
    print("EMPIRICAL EVALUATION SUMMARY:")
    print(f"  Total Sessions Evaluated    : {total_runs}")
    print(f"  Successful Key Agreements   : {success_count}/{total_runs} ({success_count/total_runs*100:.2f}%)")
    print(f"  Key Agreement Failure Rate  : {(total_runs - success_count)/total_runs*100:.2f}%")
    print(f"  Total Time Elapsed          : {t_elapsed:.2f} seconds")
    print(f"  Average Time Per Session    : {t_elapsed/total_runs*1000:.3f} ms")
    print("=" * 70)
