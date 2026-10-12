# ARMOR-PQ: A Lightweight Memory-Efficient Lattice-Based Mutual Authentication Scheme for the Internet of Medical Things

[![Language: C](https://img.shields.io/badge/Language-C99-blue.svg)](https://en.wikipedia.org/wiki/C99)
[![Language: Python](https://img.shields.io/badge/Language-Python%203-brightgreen.svg)](https://www.python.org/)
[![Verification: ProVerif](https://img.shields.io/badge/Verification-ProVerif%202.05-orange.svg)](https://bblanche.gitlabpages.inria.fr/proverif/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Official implementation, empirical simulation testbeds, and formal verification models for the research paper:

> **ARMOR-PQ: A Lightweight Memory-Efficient Lattice-Based Mutual Authentication Scheme for the Internet of Medical Things**  
> Submitted to *Scientific Reports* (Nature Portfolio).

---

## Abstract Overview

The proliferation of the Internet of Medical Things (IoMT) exposes medical devices to physical key-extraction and emerging quantum cryptanalytic attacks. **ARMOR-PQ** introduces a lightweight, hardware-rooted post-quantum mutual authentication protocol tailored for ultra-constrained medical sensors. 

### Key Architectural Highlights
- **Stateless Zero-NVM Trust:** Eliminates persistent non-volatile storage (Flash/EEPROM) of secret keys on IoMT nodes by combining silicon-rooted SRAM Physical Unclonable Functions (PUFs) with Ring-LWE (RLWE) cryptography. Private keys exist in volatile SRAM only during active protocol execution ($\approx 1.05$ ms).
- **In-Place Harvey Butterfly NTT:** Stores precomputed twiddle factors strictly in Flash/ROM ($2.0$ KB), completely eliminating dynamic scratchpad buffers. Active polynomial memory is reduced to exactly $1.0$ KB ($n = 512, q = 12289$, 16-bit `int16_t` words). Total peak device SRAM is tightly bounded by $\approx 4.8$ KB.
- **Bandwidth Efficiency:** Packed 14-bit coefficient encoding transmits the entire 3-round mutual authentication handshake in **$2{,}152$ bytes ($17{,}216$ bits)**, easily fitting within 9 standard Bluetooth Low Energy (BLE 5.0) packets.
- **Peikert Error Reconciliation:** Replaces naive rounding with 1-bit cross-rounding hints ($w \in \{0,1\}^{512}$, $64$ bytes), guaranteeing robust shared key agreement under RLWE noise.
- **Noise-Resilient Fuzzy Extractor:** Employs an optimal $[15, 1, 15]$ repetition code with majority-logic decoding capable of tolerating bit-error rates (BER) up to $10\%$, ensuring whole-key recovery success rate $P_{\text{key}} \ge 99.14\%$.
- **Triple-Tier Security Validation:** Formally proved under the Random Oracle Model (ROM), verified symbolically under the Dolev–Yao model using **ProVerif 2.05** (zero counterexamples), and concretely quantified with the **SageMath LWE Estimator** ($\approx 150$ bits post-quantum security, exceeding NIST Level 1).
- **Execution Efficiency:** Completes mutual authentication in **$0.785$ ms** ($784.994\ \mu\text{s}$) under pipelined execution ($1.306$ ms in full interactive cold-start mode) across the Raspberry Pi 400 (CPD) and Intel Xeon w3-2435 (Server) evaluation platforms.

---

## Repository Structure

```text
RLWE_PUF_ARMOR_PQ/
├── c_src/                     # Embedded C implementation & benchmarks
│   ├── main_puf_demo.c        # End-to-end benchmark & demo harness
│   ├── rlwe_puf_auth.c / .h   # 3-Round ARMOR-PQ protocol logic
│   ├── rlwe_core.c / .h       # RLWE polynomial operations & Gaussian sampling
│   ├── ntt.c / .h             # In-place Harvey butterfly NTT & twiddle tables
│   ├── sha_portable.c / .h    # Portable SHA-512 cryptographic hash
│   ├── puf_optimized.c / .h   # SRAM PUF modeling & helper data extraction
│   ├── puf_timing_measured.c  # Execution timing microbenchmarks
│   └── Makefile               # Compilation script (GCC -O2)
├── simulation/                # Empirical Monte Carlo simulation testbeds
│   ├── simulate_ake.py        # 10,000-session Monte Carlo key agreement validation
│   ├── test_ber.py            # PUF BER error-correction analysis
│   └── test_ber2.py           # Repetition code parameter sweeps
├── formal_verification/       # Symbolic security proofs
│   ├── test_proverif.pv       # ProVerif 2.05 protocol model & equational theory
│   └── proverif_output.txt    # Complete verification log output
├── .gitignore
├── LICENSE                    # MIT License
└── README.md
```

---

## Prerequisites

- **C Toolchain:** `gcc` (version 9.0 or higher), `make`
- **Python:** Python 3.8+ with `numpy` and `scipy`:
  ```bash
  pip install numpy scipy
  ```
- **ProVerif:** [ProVerif 2.05+](https://bblanche.gitlabpages.inria.fr/proverif/) (for automated symbolic verification)

---

## Quickstart & Replication

### 1. Build and Run the C Implementation
To compile the C implementation using `-O2` optimization and run the complete mutual authentication demo:

```bash
cd c_src
make clean && make
./rlwe_puf_auth_demo
```

### 2. Run Repeated Monte Carlo AKE Simulations
To validate key agreement across repeated trials under RLWE Gaussian noise:

```bash
python3 simulation/simulate_ake.py
```
This executes the 3-round protocol across automated sessions, testing both the fuzzy extractor and Peikert reconciliation ($K_D = K_S$).

### 3. Run PUF Bit Error Rate Analysis
To evaluate whole-key reconstruction probability across varying physical bit-error rates ($p \in [0.01, 0.20]$):

```bash
python3 simulation/test_ber2.py
```

### 4. Execute Formal Verification (ProVerif 2.05)
To execute symbolic security verification of injective mutual authentication and session key secrecy under the Dolev–Yao model:

```bash
proverif formal_verification/test_proverif.pv
```

**Verified Properties:**
- `query secret SK`: Session key secrecy (**Verified True**)
- `query not attacker(v_i)`: Credential privacy (**Verified True**)
- `inj-event(end_server) ==> inj-event(begin_device)`: Injective server authentication (**Verified True**)
- `inj-event(end_device) ==> inj-event(begin_server)`: Injective device authentication (**Verified True**)
- `query not attacker(devID)`: Device anonymity & untraceability (**Verified True**)

The full verification log is available in [`formal_verification/proverif_output.txt`](formal_verification/proverif_output.txt).

---

## Parameters Summary

| Parameter | Notation | Value | Rationale |
| :--- | :---: | :---: | :--- |
| Ring Dimension | $n$ | $512$ | Negacyclic ring $\mathcal{R}_q = \mathbb{Z}_q[x]/\langle x^n + 1 \rangle$ |
| Modulus | $q$ | $12289$ | Prime $q \equiv 1 \pmod{1024}$, admits NTT primitive roots |
| Error Width | $\sigma$ | $3.2$ | Discrete Gaussian $\chi_\sigma$ ($\alpha \approx 0.0006527$) |
| Packing Width | $\lceil \log_2 q \rceil$ | $14$ bits | Over-the-air polynomial transmission ($896$ B / poly) |
| Active Word Size | --- | $16$ bits | In-memory `int16_t` runtime storage ($1{,}024$ B / poly) |
| Total Communication | $|\mathcal{M}_1| + |\mathcal{M}_2| + |\mathcal{M}_3|$ | **2,152 bytes** | $1{,}064$ B ($\mathcal{M}_1$) + $1{,}024$ B ($\mathcal{M}_2$) + $64$ B ($\mathcal{M}_3$) |
| Peak SRAM | --- | **$\approx 4.8$ KB** | $1{,}024$ B NTT + $1{,}024$ B $e_i$ + $1{,}024$ B $sk_i$ + $512$ B PUF + I/O |
| ROM Twiddle Tables | $M_{\text{twiddle}}$ | **$2.0$ KB** | Flash-resident `const PROGMEM` constants |
| PUF ECC | $[N, K, D]$ | $[15, 1, 15]$ | Repetition code with majority-logic decoding ($t=7$) |
| Pipelined Latency | $T_{\text{CPD}} + T_S$ | **0.785 ms** | $699.024\ \mu$s (Raspberry Pi 400) + $85.970\ \mu$s (Intel Xeon w3-2435) |
| Cold-Start Latency | $T_{\text{CPD}} + T_S$ | **1.306 ms** | $1{,}050.798\ \mu$s (CPD) + $255.354\ \mu$s (Server), strictly on-demand |
| Post-Quantum Security | Core-SVP | **$\approx 150$ bits** | BDD $\beta=566$ under quantum sieving ($2^{0.265\beta}$) |

---

## Citation

If you find this work or artifacts useful in your research, please cite:

```bibtex
@article{tazeen2024armor,
  title={{ARMOR-PQ: A Lightweight Memory-Efficient Lattice-Based Mutual Authentication Scheme for the Internet of Medical Things}},
  author={Tazeen, Shazia and Padmavathy, R.},
  journal={Scientific Reports},
  year={2024},
  publisher={Nature Publishing Group}
}
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
