# Engineering PQC Implementations: From the NIST Call to Implementation Pitfalls, Side Channels, and Testing

Sep 25, 2026 · @jieyu

## 0. Overview

The main conclusion first. Most bugs in PQC implementations are not in the "math". They sit at the **boundary between the spec and the code** (byte order, encoding, bounds checks, rejection-sampling counters). The rest come from **semantic drift introduced by optimization** (intermediate overflow, lazy-reduction ranges, compiler-introduced branches or divisions). The problems exposed in NIST Round 3, KpqC, and the first round of NGCC are strikingly similar.

This tutorial is for researchers who already write AVX2/AVX-512/NEON optimized code and want a systematic methodology for high-assurance implementations. Suggested reading path:

1. Skim Sections 1–2 (history and scheme landscape) to get oriented.
2. Read Sections 3–5 (workflow, core operations, pitfalls) carefully, and check your own code against them item by item.
3. Use Sections 6–7 (side channels, testing) to set up CI as needed.
4. Section 8 is a resource index by topic. Section 9 is a pre-submission checklist.

Note: links marked \[source\] were checked during this review. Unmarked statements are common knowledge in the field or approximate descriptions. Please verify against the original before citing.

Follow-up post: test layer 6 in Section 7.1 (property and metamorphic testing) is covered in detail in [Flip One Bit: What Cryptographically-Informed Testing Finds in PQC Implementations](../crypto-informed-testing/). It includes a minimal test program for the bit-flip checks in checklist sections B and C.

## 1. A Short History of Standardization

NIST took 8 years, from the 2016 call to the 2024 release of FIPS 203/204/205. In every round, some candidates were dropped for implementation or design problems. The NGCC first-round public review found a large number of issues within days. This shows that review tooling, especially AI-assisted review, has made "audited on submission" the norm.

### 1.1 NIST PQC timeline (newest first)

| Date | Event | Lesson for implementers |
| --- | --- | --- |
| 2026-07 | The HAWK team withdrew its signature scheme after an AI-assisted attack was published [source](https://www.nist.gov/news-events/news/2026/05/nine-candidates-advance-third-round-additional-digital-signatures-pqc) | Design-level auditing is speeding up too |
| 2026-05 | Additional signatures Round 3: FAEST, HAWK, MAYO, MQOM, QR-UOV, SDitH, SNOVA, SQIsign, UOV; CROSS, LESS, Mirath, PERK, RYDE eliminated [NIST IR 8610](https://csrc.nist.gov/pubs/ir/8610/final) | Requirements on multivariate, MPCitH/VOLEitH, and isogeny implementations will tighten quickly (constant time, physical attacks) |
| 2025-09 | 6th NIST PQC Conference; FIPS 206 (FN-DSA) draft progress report [slides](https://csrc.nist.gov/presentations/2025/fips-206-fn-dsa-falcon) | Floating-point vs. fixed-point issues in FN-DSA are still under discussion |
| 2025-03 | HQC selected as the second KEM (code-based, a backup for diversity) | The HQC standard text is not final; implementations must track the draft |
| 2024-10 | Additional signatures Round 2 (14 candidates) | — |
| 2024-08-13 | FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA finalized | There are subtle differences between Kyber/Dilithium and ML-\* (see 3.3) |
| 2023-08 | Initial public drafts of FIPS 203/204/205; additional signatures Round 1 with 40 candidates | During the draft period, many implementations were incompatible between draft and final |
| 2022-07 | End of Round 3: Kyber, Dilithium, Falcon, SPHINCS+ selected; BIKE/HQC/McEliece/SIKE move to Round 4 | — |
| 2022-07/08 | SIKE broken by Castryck–Decru; Rainbow broken by Beullens (February of the same year) | A mathematical structure can collapse entirely; implementations need crypto agility |
| 2020-07 | Round 3: 7 finalists + 8 alternates | NIST explicitly includes embedded data such as pqm4 in the evaluation |
| 2019-01 | Round 2: 26 candidates | — |
| 2017-12 | Round 1: 69 of 82 submissions accepted [NIST IR 8240](https://nvlpubs.nist.gov/nistpubs/ir/2019/NIST.IR.8240.pdf) | Many implementation bugs and breaks appeared quickly after the first round went public |
| 2016-12 | NIST formal call for proposals (FRN) | — |

Status (as of 2026-09): FIPS 206 FN-DSA is still not final. HQC has been selected, but its standard text is still pending. Check the [NIST PQC project page](https://csrc.nist.gov/projects/post-quantum-cryptography) before citing.

### 1.2 Other standardization efforts

- **China NGCC (hosted by ICCS)**: launched in February 2025; first-round candidates announced on 2026-09-20. The public-key track has 34 signature, 41 KEM, and 9 key-exchange candidates. There is also a hash track with 35 candidates. ICCS published all materials, required English specs, provided a unified API, and runs a public forum [source](https://postquantum.com/security-pqc/china-ngcc-candidate-flaws/).
- **NGCC first-round public audit**: [ngcc.dev](https://ngcc.dev/reports/index.html), maintained by Saarinen, lists 147 valid findings as of 2026-09-25: 65 implementation, 53 design, and 29 side-channel. Saarinen states that all findings he wrote were AI-assisted.
- **Korea KpqC**: started in 2021 with a Round 0. Winners announced in January 2025: HAETAE and AIMer (signatures), SMAUG-T and NTRU+ (KEMs). In its first round, one work systematically ran Valgrind constant-time checks, memory-leak checks, and metamorphic testing on all candidates [ePrint 2023/1437](https://eprint.iacr.org/2023/1437.pdf). It is a good reference point for NGCC.
- **ISO/IEC 18033-2 revision**: includes FrodoKEM, Classic McEliece, ML-KEM, and others. In Europe, BSI and ANSSI recommend FrodoKEM/McEliece more strongly than NIST does.
- **IETF**: TLS hybrid key exchange (X25519MLKEM768), LAMPS certificate OIDs, and CFRG documents for X-Wing and ML-KEM. Implementers should follow the decisions on key encoding (seed format vs. expanded format).
- **Other countries and industries**: CNSA 2.0 (US National Security Systems), lattice-based schemes in Chinese cryptography industry standards (e.g., the CTRU industry standard draft), and others.

## 2. Scheme Landscape: KEM / Signatures / KEX

It is more useful to remember schemes by their mathematical family than by name. Schemes in the same family share almost the same implementation pitfalls: lattices → NTT/sampling/FO; codes → constant-time decoders; multivariate → Gaussian elimination pivots; hash-based → address/index encoding; MPCitH → seed trees and commitments.

### 2.1 NIST standards and main candidates

| Scheme | Type | Math basis | Status (2026-09) | Implementation challenges |
| --- | --- | --- | --- | --- |
| ML-KEM (Kyber) | KEM | Module-LWE | FIPS 203 | NTT, division in compression, FO implicit rejection, public-key modulus check |
| HQC | KEM | QC Hamming-metric codes | Selected, standard pending | Constant-time RS/RM decoding, fixed-weight sampling, large polynomial multiplication |
| Classic McEliece | KEM | Goppa codes | ISO track; not selected by NIST | Huge public keys, constant-time Gaussian elimination, bitsliced root finding |
| FrodoKEM | KEM | Unstructured LWE | ISO track | Matrix-generation bandwidth, CDF sampling |
| BIKE | KEM | QC-MDPC | Not selected in Round 4 | Constant-time BGF iterative decoding, failure rate |
| NTRU / NTRU Prime (sntrup761) | KEM | NTRU lattices | Not selected in Round 3; sntrup761 is the OpenSSH default | NTT-unfriendly ring, inversion, constant-time sorting |
| ML-DSA (Dilithium) | Signature | Module-LWE/SIS | FIPS 204 | Rejection-sampling loop, hint encoding/decoding, strong unforgeability |
| FN-DSA (Falcon) | Signature | NTRU lattice trapdoor | FIPS 206 draft | Constant-time floating-point FFT and discrete Gaussian sampling, cross-platform floating-point consistency |
| SLH-DSA (SPHINCS+) | Signature | Hash-based | FIPS 205 | ADRS address encoding, index truncation, fault attacks |
| LMS / XMSS | Stateful signature | Hash-based | SP 800-208 | State management (never reuse an index) |
| UOV / MAYO / QR-UOV / SNOVA | Signature | Multivariate | Additional signatures Round 3 | GF(16)/GF(256) table lookups, constant-time elimination |
| FAEST / MQOM / SDitH | Signature | VOLEitH / MPCitH | Additional signatures Round 3 | GGM trees, commitments, constant-time AES/field arithmetic |
| SQIsign | Signature | Isogenies | Additional signatures Round 3 | Big-integer/quaternion arithmetic, verifier input validation |

### 2.2 KpqC winners (Korea)

HAETAE (lattice signature, uniform distribution over a hypersphere + rejection sampling), AIMer (symmetric primitives + MPCitH), SMAUG-T (hybrid MLWE/MLWR KEM), NTRU+ (NTRU KEM).

### 2.3 NGCC first-round candidates (by family)

Source: family labels in the [ngcc.dev report index](https://ngcc.dev/reports/index.html). Each name is followed by its official ID.

**KEM (41)**

- Lattice (MLWE/RLWE/MLWR/LWE): Aigis-Enc+ (kem-01), Amoeba (02), BW-KEM (08), CheetahKEM (09), COMPASS-KEM (11), CTL (12), DKEM (13), FLIT (15), LoongKEM (18), Lore (19), MAMBA-Frost/Viper (20/21), Mithril (22), MORNING-Scabbard (24), NEV (25), Polar-KEM (29), PolarLAC (30), Rudraksh2 (34), Scloud+ (35), WeaverKEM (39), ZEN (41)
- Lattice (NTRU): DTRU (14), NTRE (27), OAEP-NTRU (28), YuanYang.KEM (40)
- Code (rank metric): BAG-Loong/Piglet (03/04), BRA (06), BRQC (07), C-Multi-UR-AG (10)
- Code (Hamming/QC/other): BIKE-MLThre (05), HARE (16), HEP-QC (17), Mito (23), NSS-HQC (26), QCTM (32), QUBE (33), TRIKE (36), TriQ-KEM (37), UVW KEM (38)
- Isogeny: QIMEN-PIKE (31)

**Signatures (34)**

- Lattice (Fiat–Shamir): Aigis-Sig+, CS, MORNING-ATLAS, as well as BiT, COMPASS-SIG, DARTS, Octarine, OPS, Rhyme, Shuttle
- Lattice (hash-and-sign): YuanYang.DSA
- Hash-based: CEDRUS+C, CEDRUS-alpha, FlexTree, Phoenix
- Multivariate: DOVE, Facto-DSA, Origami, TSUOV, UVW, VDOO
- MPCitH / VOLEitH: Chinith, Galas, GreatWall, Lynxer, Sigurd, Tins, TRINE, SYDO, ReSolveD-ɑ
- Code: Qing Luan
- Isogeny: SQIsign2D2, SQIsign2D-push1/2, SQIsignTriangle

**Key exchange (9)**

ADKEX, AFS-KEX, CreTAKE, DKEX, Loom, MAMBA-NIKE, NEV-AKE (lattice AKE/NIKE), NIIKE (isogeny NIKE), TriQ-KEX (code-based AKE).

### 2.4 Historical background of KEX

NIST only called for KEMs and had no separate KEX track. This is a clear difference between NGCC and NIST. Classic works worth knowing: Ding key exchange (2012), BCNS (2015), NewHope (2016, Google's CECPQ1 experiment), Frodo key exchange (2016), CSIDH (2018, isogeny NIKE), SWOOSH (2023, lattice NIKE). In practice, AKE is usually built at the protocol layer from a KEM plus a signature (TLS 1.3, KEMTLS, PQ-Noise).

## 3. General Implementation Workflow

Mature teams (PQ Code Package, PQClean, pqm4, liboqs, BoringSSL/AWS-LC) share a common practice: **executable spec → clean reference implementation → multiple test layers that pin down behavior → then optimize**. Every optimized implementation uses the reference implementation as its differential baseline. Reversing the order (write the fast code first, add tests later) is the main source of the NGCC problems.

### 3.1 Phases

1. **Close reading of the spec and a formal summary**
   - Rewrite each algorithm as pseudocode. Annotate each variable with its type, length (bits or bytes), value range, and byte order.
   - List every "input validation" step (public-key modulus check, ciphertext length, hint format, zero padding bits) and every domain-separation constant.
   - Do a "security budget check" for each parameter set: do the seed length, hash output length, challenge space, and salt length cover the claimed security level? Many critical NGCC issues fail exactly here.
2. **Executable specification**
   - Write a model in Python/SageMath or hacspec/Rust. It should not aim for performance, should follow the spec line by line, and should be independent of the C code.
   - This is the ground truth for all later differential testing. Ideally, a different person writes it.
3. **Reference implementation (C99, portable)**
   - Follow the [PQClean requirements](https://github.com/PQClean/PQClean): valid C99, `-Wall -Wextra -Wpedantic -Werror`, no out-of-bounds writes through the API, identical output on big/little endian and 32/64-bit, and no Valgrind or ASan errors.
   - The reference implementation must also be constant time. It is the first thing reviewers look at.
4. **Test vectors and test framework (see Section 7)**
   - KATs, intermediate-value vectors, negative test vectors, cross-platform consistency.
5. **Optimized implementations (AVX2/AVX-512/NEON/Cortex-M4/RISC-V V)**
   - Differentially test each kernel against its reference function with random inputs, including boundary inputs.
   - Record the input/output coefficient-range invariants of each kernel, and check them with assertions or range-analysis tools.
6. **Verification and hardening**
   - Constant-time checking, fuzzing, formal verification (e.g., Jasmin/EasyCrypt, CBMC, HOL-Light), third-party audits.
7. **Release and maintenance**
   - State clearly which spec version the code implements. Update the vectors with every tweak. Keep the issue tracker open.

### 3.2 Reference projects

| Project | Role | What to learn |
| --- | --- | --- |
| [PQ Code Package](https://github.com/pq-code-package) (mlkem-native, mldsa-native) | Production-grade ML-KEM/ML-DSA under the Linux Foundation PQCA | CBMC proofs of memory safety + HOL-Light proofs of functional correctness for assembly kernels; contract-style comments on coefficient ranges |
| [PQClean](https://github.com/PQClean/PQClean) | Collection of clean, portable implementations; planned to be archived from 2026-07 | Automated quality-gate checklist; the companion paper [ePrint 2022/337](https://eprint.iacr.org/2022/337) summarizes typical problems in submitted code |
| pqm4 / pqmx | Benchmarks and tests on Cortex-M4/M55 | Stack usage, embedded kernels, hardware RNG interfaces |
| liboqs / oqs-provider | Unified API + OpenSSL provider | Cross-scheme testing, CI, real integration issues |
| libjade / formosa-crypto | High-assurance implementations in Jasmin | Proofs of functional correctness + constant time + Spectre protection |
| SUPERCOP | Large-scale benchmarking | Comparison across many compilers and flags; exposes undefined behavior |

### 3.3 Subtle differences between the "paper version" and the "standard version" (NIST as an example)

- **ML-KEM vs. Kyber r3**: in K-PKE key generation, the input to G now includes k for domain separation. Encapsulation no longer hashes m, and the shared key no longer mixes in H(c). Input validation was added for encapsulation (public-key modulus check) and decapsulation (secret-key hash check).
- **ML-DSA vs. Dilithium r3**: a context string and a pre-hash mode were added. tr became 64 bytes. The length of the challenge hash c\~ depends on the security level. Hint decoding gained a check that prevents malleability.
- **SLH-DSA vs. SPHINCS+ r3.1**: changes to message hashing and address handling details; a context was added.

In the same way, tweaks after NGCC enters Round 2 will create "old vectors, new spec" mismatches. We recommend adding a "change log" subsection to the spec for every change.

## 4. Core Operations: Implementation Notes

The performance bottleneck is almost always polynomial multiplication and hashing/XOF. The correctness bottleneck is almost always range analysis, sampling, and encoding. Below, for each operation, we list the invariants that must be made explicit.

### 4.1 Polynomial multiplication

- **NTT-friendly rings** (ML-KEM q=3329, ML-DSA q=8380417)
  - Be explicit about the representation: signed \[-q, q\] or unsigned \[0, q), Montgomery domain or normal domain. After each butterfly layer, write down the bound on the absolute value of the coefficients.
  - Lazy reduction is key to performance and also the main source of overflows. With int16 storage, the range doubles at each layer, so you must work out at which layers a Barrett reduction is required.
  - Kyber's "incomplete NTT" (7 layers + base multiplication of degree-2 factors), the bit-reversed order of twiddles, and merging n^-1 with the Montgomery factor at the end of the inverse NTT: these constants are best generated by a script and compared against the model.
  - Alternative reductions: Montgomery, Barrett, and Plantard (work by Huang et al. on Cortex-M4). They have different input and output ranges. When mixing them, check each layer carefully.
- **NTT-unfriendly rings** (NTRU, sntrup761, Saber, most NTRU/LWR candidates in NGCC)
  - Options: Toom-Cook/Karatsuba; NTT over a large modulus and then mapping back (the output range must not exceed half of the large modulus); multiple moduli + CRT; Good's trick, Rader, mixed radix. See Chung et al., "NTT Multiplication for NTT-unfriendly Rings" (TCHES 2021).
  - Key latent bug: is the maximum possible coefficient of the product really less than half of the chosen modulus? If the assumption on the secret-key coefficient range is broken by a malicious ciphertext or public key, you get a wrong result that "looks normal".
  - Polynomial inversion (NTRU key generation): use constant-time divsteps (Bernstein–Yang) or inversion by exponentiation. Avoid the data-dependent branches of the extended Euclidean algorithm.
- **Code-based schemes**: GF(2)\[x\] multiplication uses PCLMULQDQ/VPCLMULQDQ or bitslicing. If a sparse × dense multiplication accesses memory at secret support positions, it is a cache side channel (NGCC kem-33 is such a case).

### 4.2 Sampling

- **Uniform rejection sampling** (SampleNTT/ExpandA): variable time is fine when the input is a public seed. But you must handle the case where the XOF output runs out, and the tail handling of the vectorized version must match the scalar version byte for byte.
- **Centered binomial distribution (CBD)**: constant-time popcount; watch out for reads that cross byte boundaries when η=3.
- **Rejection sampling on secret inputs**: e.g., fixed-weight vector sampling in HQC. The number of rejections leaks information about the seed, and Guo et al. used this in a practical timing attack ("Don't Reject This", TCHES 2022). The correct approach is constant-time sampling (e.g., Sendrier's method, or a random permutation via a sorting network). NGCC kem-33/kem-37/kex-09 all re-expand a secret seed with a variable-length sampler during decapsulation.
- **Discrete Gaussian** (Falcon/FN-DSA, YuanYang.DSA): constant-time CDT or Bernoulli rejection. Floating-point consistency and constant-time behavior across platforms (x87/FMA/soft float) must both be verified. A wrong covariance directly leaks the secret basis (NGCC sign-34-1).
- **The masking vector y in signatures**: the nonce/counter of each rejection iteration must increase and must not wrap around. Repeated masking coefficients leak the secret key (NGCC sign-15-4).

### 4.3 Encoding, compression, and decoding

- The division in compression round(2^d/q · x) is the root cause of KyberSlash. Replace it with multiply + shift, and verify exhaustively.
- **Decoding must be injective**: re-encoding a decoded value must give back the original byte string. For public keys this is the "modulus check". For signatures it is "strong unforgeability". For ciphertexts it is a precondition for the FO re-encryption comparison. Many "signature malleability" and "public-key aliasing" problems in NGCC (sign-01-1, sign-15-2, sign-34-2) fall into this category.
- Padding bits, unused high bits, monotonicity of hint positions: check each of them explicitly.

### 4.4 Hash / XOF

- Check output lengths against the "birthday bound": a signature at the 256-bit security level whose message representative is only 512 bits long has only 256-bit collision resistance. The same applies to seed lengths. More than a dozen NGCC candidates were rated critical for issues of this kind.
- Domain separation: prefix/suffix constants for each call, nonce byte positions, length encodings. Each lane of a multi-way parallel Keccak (x4/x8) must be compared byte by byte with the single-lane implementation.
- Incremental squeezing is most error-prone at rate boundaries (168 bytes for SHAKE128, 136 bytes for SHAKE256). Also, Merkle–Damgård hashes such as SM3 cannot be used directly as an XOF.

## 5. Easily Overlooked Implementation Issues (with Real Cases)

The 65 implementation findings in the NGCC first round fall into 9 categories. Almost every category has a precedent in the NIST process or in production libraries. The first 5 categories have nothing to do with optimization: the problems already exist in the reference implementation. Section 5.2 lists the problems introduced by optimized implementations.

### 5.1 Classification table

IDs refer to the [ngcc.dev reports](https://ngcc.dev/reports/index.html).

| Category | Typical symptoms | NGCC examples | Defenses |
| --- | --- | --- | --- |
| 1. Security budget truncated by the code | 256-bit seeds at the 384/512-bit level; message representative or prehash too short; challenge space smaller than the claimed level; bit/byte confusion | kem-11-1, kem-21-1, kem-27-1, kex-06-1, sign-06-1/2, sign-15-3, kex-03-1 (ephemeral secret reduced to 64 bits) | Static assertions in parameter headers that each length ≥ its security budget; put units in names (`_BYTES`/`_BITS`) |
| 2. Wrong FO transform implementation | Implicit rejection ineffective; mask covers only some bytes; re-encryption comparison checks only part of the ciphertext; rejection key not bound to the full ciphertext | kem-01-1, kem-09-1, kem-18-1, kem-02-1 (compares only every 4th byte), kem-13-1 | Negative tests with invalid ciphertexts: after flipping each bit of the ciphertext, decapsulation must output a deterministic pseudorandom key that differs from the correct key |
| 3. Randomness problems | KAT deterministic RNG left in the real code path; first encapsulation in a process is reproducible; ephemeral key generated only once; predictable signing randomness | kem-17-1/3, sign-12-1, sign-33-1/4, kex-02-1, kex-08-2 | Separate KAT RNG and production RNG at compile time; test that "two calls must produce different outputs" |
| 4. Input parsing and memory safety | Malicious hint count causes stack writes; caller-declared length overflows a stack buffer; all-zero signature crashes or triggers an assert; verification result depends on uninitialized stack data; allocation failure returns success | sign-01-2, kem-14-1 (DTRU), sign-25-1, sign-27-1, sign-32-1/2, kem-10-1, kem-31-1, hash-02-1 | Fuzzing + ASan/UBSan/MSan; compare every external length against constants; failure paths return an error code by default and zero the output |
| 5. Non-injective encoding / malleability | Signature padding bits not checked; hint encoding has multiple valid representations; public-key packing has aliases | sign-01-1, sign-07-1, sign-15-2, sign-11-5, sign-34-2 | "Decode → re-encode → byte-for-byte equal" as a precondition for verification; mutation tests targeting SUF-CMA ([details](../crypto-informed-testing/)) |
| 6. Code does not match the spec | Missing rounding constant; error polynomial discarded; a layer of error-correction decoding missing; address truncated to 8 bits; different hash instantiation | kem-24-1, kem-40-1, kem-39-2, kem-23-1, sign-04-2/3, sign-03-1 | Independent executable spec + differential testing of intermediate values (not just final outputs) |
| 7. State management | Protocol state can be reset; state reuse leaks the key | kex-05-2; also the state-reuse issue in the Threshold ML-DSA reference code [source](https://www.projecteleven.com/blog/nine-schemes-advance-to-round-3-of-nists-additional-digital-signatures-process) | Make the state machine explicit; destroy state after use |
| 8. Protocol-level omissions | Identity hard-coded to zero; malicious public key breaks contributiveness; raw shared value not passed through a KDF | kex-07-1, kem-13-2, kex-08-1 | KDF input includes the full transcript; model malicious peers |
| 9. Leftover debug code | Debug path keeps the secret error vector; submission package ships a complete attack script | kem-32-1, kem-29-1 | Before release, `grep` for printf/DEBUG/global variables; review every file in the package |

Historical precedents: the FO ciphertext comparison in several NIST candidates, including FrodoKEM, once used a non-constant-time memcmp (Guo–Johansson–Nilsson, CRYPTO 2020). In 2019, the Falcon reference implementation produced signatures with the wrong distribution because of a sampler bug.

### 5.2 Problems introduced by optimized implementations (key section)

1. **Range overflow**: lazy reduction, delayed Barrett, `vpmulhw` keeping only the high 16 bits, saturation/accumulation in `vpmaddwd`. These never fail on normal inputs and are only triggered by malicious ciphertexts or extreme secrets. Test every kernel with "maximum absolute value" inputs.
2. **Tails and out-of-bounds access**: when n is not a multiple of the vector width (e.g., 761 in sntrup761, prime dimensions in NTRU), the code may read or write one extra vector. For buffers with alignment padding, make sure the padding is zero and is not written to the output (see sign-01-4 and kem-06-2, "writes one extra polynomial / one extra limb").
3. **Vectorized rejection sampling**: table-based shuffle compaction writes more elements than the number of valid coefficients at the end of the buffer. Allocate slack space, and compare "XOF bytes consumed" against the scalar version.
4. **Coefficient order**: AVX2 implementations often use a non-standard order (the NTT domain after shuffles), which must be restored before serialization/deserialization. If the whole implementation is internally consistent, the KAT will still fail. But if only one internal function is called from outside, the error can be hidden.
5. **Compiler-introduced branches**: `poly_frommsg` in the Kyber reference code is constant time at the source level. But Clang 15–18 with options such as `-Os` generates a secret-dependent branch, which allows recovering an ML-KEM-512 secret key in about 10 minutes (CVE-2024-37880) [source](https://github.com/antoonpurnal/clangover). Ternary operators, bool-to-int conversion, and `x ? a : b`-style cmov are all unreliable.
6. **Variable-time instructions**: division and modulo (KyberSlash1/2, key recovery in hours and minutes on Cortex-A7/M4 respectively [ePrint 2024/1049](https://eprint.iacr.org/2024/1049)); multiplication on some embedded platforms (early termination of `UMULL` on Cortex-M3); floating-point subnormals.
7. **Undefined behavior**: signed overflow, left shift of negative numbers, accessing a byte buffer through a misaligned `uint32_t*` (strict aliasing). Compilers "optimize" based on these into code with different semantics, and the behavior changes with compiler version.
8. **Zeroization removed**: `memset` on secret buffers can be removed by dead-store elimination. Use `explicit_bzero`, a volatile function pointer, or a compiler barrier. Also consider leftover ymm/zmm contents in registers and on the stack.
9. **Inconsistent runtime dispatch**: when AVX2/AVX-512 paths are selected by CPUID, all paths must behave identically byte for byte on malicious inputs (including return codes). Otherwise it is both a cross-platform interoperability problem and a security problem. Memory aliasing (input and output in the same buffer) is often untested in vectorized code.
10. **Embedded-specific issues**: exceeding stack space (roughly tens of KB on M4), unchecked `randombytes` return values, hardware TRNG health tests, and table lookups that still leak on cached M7/M55.
11. **Floating point** (FN-DSA-like schemes): FMA contraction, x87 extended precision, and `-ffast-math` can change results or timing. Compare signature bytes across platforms.

## 6. Side-Channel Protection

The minimum requirement for software implementations is "constant time". More precisely: **secret-independent control flow, memory addresses, and operands of variable-time instructions**. It must be verified at the **binary level**. ngcc.dev did a source-level constant-time review of all 119 candidates, and almost all of its 29 side-channel findings fall into these three categories [source](https://ngcc.dev/constant-time/index.html).

### 6.1 Three leakage sources and NGCC examples

| Leakage source | Typical code pattern | NGCC examples | Safe approach |
| --- | --- | --- | --- |
| Secret-dependent branches | Branching on the sign of decrypted coefficients; pivot selection in multivariate elimination; branching when mapping coefficients to a secret center; hash branching on the last bit of the message | kem-08-1 (BW-KEM), kex-02-2, sign-31-2, sign-33-5, kem-03-1, hash-01-1 | Arithmetic masking + conditional swaps; constant-time Gaussian elimination (masked addition on every row, no early exit) |
| Secret-dependent memory addresses | S-box/T-table lookups; sparse polynomials accessed by support position; decoders indexing tables by syndrome; secret permutations | hash-05/11/21/22/27, kem-02-2, kem-06-3, kem-17-5, kem-33-2, kem-40-2, sign-18-4 | Bitslicing; full table scan + masked selection; permutations via sorting networks (djbsort) |
| Variable-time instructions / variable workload | Division and modulo; rejection sampling driven by a secret seed; decoders whose iteration count depends on secrets | kem-33-1, kem-37-1, kex-09-1, hash-35-1 | Multiply + shift instead of division; fixed iteration counts; constant-time fixed-weight sampling |

### 6.2 The most dangerous pattern for KEMs: plaintext-checking oracles

For KEMs built with the FO transform, any small leak related to the decrypted m (a branch, a division, a non-constant-time comparison, a retry after a decryption failure) can form a plaintext-checking oracle. It allows recovering the secret key in thousands to tens of thousands of queries. Clangover and KyberSlash both belong to this class. The "list-decoding failure oracle" and "retry behavior leaks the session key" in NGCC kem-38-2/3 use the same mechanism.

Practical rule: the entire path in decapsulation from "decrypt" to "output key" must be straight-line code. A decryption failure must not cause any observable difference in behavior, including return codes and timing.

### 6.3 Compilers and microarchitecture

- **Working against the compiler**: use a value barrier on critical mask values (e.g., `__asm__("" : "+r"(x))` or XOR with a volatile global). This is the approach Kyber adopted after fixing Clangover. Peter Schwabe's [Kyber implementation slides](https://cryptojedi.org/peter/data/cmmrs-20240801.pdf) give a good demonstration.
- **Test on a matrix of compilers × optimization levels**: major versions of gcc/clang × `-O0/-O1/-O2/-O3/-Os` × `-fno-vectorize` × LTO.
- **Microarchitectural leakage**: Spectre v1 (speculative out-of-bounds reads), Hertzbleed (power → frequency → timing, practical against SIKE), data-dependent prefetchers. The Jasmin/libjade project has a type system against Spectre. The Intel DOIT and Arm DIT flags guarantee data-independent timing for some instructions.

### 6.4 Physical side channels and fault attacks (embedded)

- **Power/EM**: single-trace attacks (belief propagation against the NTT, template attacks against CBD/message encoding), and key recovery by chosen ciphertexts + side channels (a large body of work by Ravi, Primas, Pessl, and others).
- **Masking**: arithmetic/Boolean mask conversion is the bottleneck for lattice schemes (compression, comparison, CBD, rejection sampling). See Bos et al., "Masking Kyber: First- and Higher-Order Implementations" (TCHES 2021), higher-order masked Kyber/Dilithium by Coron et al., and Raccoon, which was designed for masking.
- **Fault attacks**: differential fault attacks on deterministic signatures (Dilithium deterministic mode, WOTS chains in SPHINCS+), and skipping the FO re-encryption comparison. Countermeasures: randomized signing, recomputation checks, duplicated critical comparisons.
- **Evaluation methods**: TVLA (t-test-based leakage assessment) and open platforms such as ChipWhisperer. Note that the State Cryptography Administration of China has launched a research program on side-channel evaluation of candidate hardware implementations [source](https://postquantum.com/security-pqc/china-ngcc-candidate-flaws/). The weight of physical security will likely increase in later rounds.

### 6.5 Further reading

- Jancar et al., "They're not that hard to mitigate: What Cryptographic Library Developers Think About Timing Attacks", IEEE S&P 2022: why developers do not use constant-time tools.
- Systematic timing-leakage analysis and tooling for NIST additional signature candidates [arXiv 2509.04010](https://arxiv.org/pdf/2509.04010).
- The series of works by Ravi, Chattopadhyay, et al. on side-channel-assisted chosen-ciphertext attacks on lattice KEMs (including "Et tu, Brute?" on HQC).

## 7. Testing, Robustness, and Spec Conformance

Passing the KATs only proves agreement with the reference implementation on 100 random inputs generated by the NIST DRBG. It covers almost no malicious inputs or low-probability edge cases. Most of the NGCC problems pass the KATs. We recommend building tests in the layers below.

### 7.1 Test layers

| Layer | What it checks | Tools / resources |
| --- | --- | --- |
| 1. KAT | Agreement with the reference implementation on normal inputs | NIST `PQCgenKAT` (AES-256-CTR DRBG, for testing only) |
| 2. Internal functions / intermediate-value vectors | Locating divergence step by step; deterministic internal interfaces for KeyGen/Encaps | NIST ACVP; intermediate vectors in [C2SP CCTV](https://c2sp.org/CCTV/ML-KEM) |
| 3. Negative and boundary vectors | Public key above the modulus, wrong ciphertext length, tampered secret-key hash, "unlucky" vectors that read a lot of XOF output, vectors that fail if compared with strcmp | CCTV, [Wycheproof](https://github.com/C2SP/wycheproof), AWS-LC decapsulation validation vectors [source](https://pkg.go.dev/github.com/aws/aws-lc/util/vecgen) |
| 4. Accumulated vectors | Millions of random tests, committing only a single hash value | [Accumulated Test Vectors](https://words.filippo.io/accumulated/): inputs generated deterministically with SHAKE128, all outputs absorbed into one hash |
| 5. Differential testing | Optimized vs. reference vs. independent executable spec; at both the single-kernel level and the full API level | Custom framework; Sage/Python models |
| 6. Property and metamorphic testing | Decaps(Encaps) consistency; decode-then-encode is the identity; flipping any bit of a ciphertext/signature must lead to rejection; two keygens produce different outputs | Metamorphic testing applied to KpqC [ePrint 2023/1437](https://eprint.iacr.org/2023/1437.pdf); a full walkthrough of the method in the [follow-up post](../crypto-informed-testing/) |
| 7. Fuzzing | Robustness of parsers, verifiers, and decapsulation on arbitrary byte strings; differential fuzzing across implementations | libFuzzer, AFL++, honggfuzz; with ASan/UBSan/MSan |
| 8. Memory and undefined behavior | Out-of-bounds access, uninitialized reads, integer overflow | Valgrind memcheck, sanitizers, `-fsanitize=integer`; stack-usage measurement (M4) |
| 9. Cross-platform consistency | Big/little endian, 32/64-bit, different compilers | QEMU for s390x (big endian), i386, ARM; QEMU mps2-an386 for Cortex-M4 |
| 10. Constant time | Secret-dependent branches/addresses/variable-latency instructions | See 7.2 |
| 11. Formal verification | Proofs of functional correctness, memory safety, and constant time | See 7.3 |

### 7.2 Constant-time checking tools

- **Valgrind secret marking (ctgrind / TIMECOP)**: mark secret keys and randomness as "uninitialized" with `VALGRIND_MAKE_MEM_UNDEFINED`. Any branch or address that depends on them triggers an error. It is the cheapest option and should be the first to go into CI. Note that public values (e.g., rejection-sampling loop counts, verification results) must be explicitly "unmarked", and the documentation must argue why they are public.
- **KyberSlash-patched Valgrind**: additionally detects variable-latency instructions such as divisions with secret operands. The patch is published in the [TCHES 2025 artifact](https://artifacts.iacr.org/tches/2025/a9/readme.html).
- **Statistical: dudect**: black-box timing + t-test. Suitable for spot checks on the final binary, but coverage depends on how the input classes are designed.
- **Binary-level static/symbolic analysis**: Binsec/Rel, Microwalk (dynamic binary instrumentation), ct-verif (LLVM level).
- **Compiler matrix**: the tools above must be run across multiple compilers and optimization levels. Otherwise, problems like Clangover will be missed.

### 7.3 Formal verification toolchains

- **Jasmin + EasyCrypt** (libjade/formosa): functional correctness, constant time, and speculative constant time. Already covers the AVX2 implementation of ML-KEM.
- **CBMC + HOL Light** (mlkem-native): CBMC proves the C code free of out-of-bounds access and overflow; HOL Light (in the style of s2n-bignum) proves the functional correctness of the assembly kernels. Its style of function contracts (pre/postconditions annotating coefficient ranges) is worth learning even if you do not run the proofs.
- **hax / hacspec + F\*** (Cryspen libcrux): verification of Rust implementations.
- **Cryptol + SAW** (Galois): equivalence proofs between an executable spec and C code.
- **saferewrite** (Bernstein): uses symbolic execution to check equivalence between optimized and reference implementations. Suitable for small kernels.

### 7.4 How to check "conformance to the spec" in practice

1. Have **someone other than the code author** write an independent executable model from the spec. When it disagrees with the code, first decide whether the code or the spec is wrong, and record it in the spec errata.
2. Export intermediate values for each sub-step (seed expansion, matrix A, noise, before/after compression, hash inputs) and compare them step by step. Problems found by ngcc.dev such as "missing rounding constant" and "discarded error polynomial" can only be found by comparing intermediate values.
3. Write a negative test for every "MUST/reject" statement in the spec, and keep a traceability table from requirements to tests.
4. Validate the parameters with decryption-failure-rate statistics: measure the failure rate on variants with small parameters or amplified noise and compare with the theoretical value. This can catch failure-rate analysis errors like kem-22-1 and kem-09-3.
5. Have an AI assistant review the code against the spec clause by clause. Reviewers already do this; submitters should do it first.

## 8. Resource Index: People, Papers, Blogs, Slides, Forums

If you only read three things: the PQClean experience paper [ePrint 2022/337](https://eprint.iacr.org/2022/337), Peter Schwabe's [slides on Kyber implementation aspects](https://cryptojedi.org/peter/data/cmmrs-20240801.pdf), and reproduce the [ngcc.dev reports](https://ngcc.dev/reports/index.html) one by one.

### 8.1 Representative people in PQC engineering (by area)

| Person | Affiliation (approx.) | Representative work / what to learn |
| --- | --- | --- |
| Daniel J. Bernstein | UIC / Academia Sinica | NTRU Prime, Classic McEliece, SUPERCOP, djbsort, KyberSlash, saferewrite; long [blog](https://blog.cr.yp.to) posts on security and engineering trade-offs |
| Tanja Lange | TU/e | McEliece, isogenies, PQCRYPTO teaching materials |
| Peter Schwabe | MPI-SP | Co-designer of Kyber/Dilithium/SPHINCS+; PQClean, pqm4, Jasmin, high-assurance implementations |
| Matthias J. Kannwischer | Chelpis / PQCA | pqm4, PQClean, mlkem-native; embedded optimization and test infrastructure |
| Hanno Becker | AWS | mlkem-native, the SLOTHY assembly superoptimizer, HOL-Light-verified Arm kernels |
| Bo-Yin Yang / Vincent Hwang / Ming-Shing Chen | Academia Sinica | Multiplication in NTT-unfriendly rings, survey of Arm/AVX2 polynomial multiplication, McEliece/multivariate optimization |
| Gilles Barthe / Manuel Barbosa / Benjamin Grégoire / François Dupressoir | MPI-SP / Porto / Inria / Bristol | Jasmin, EasyCrypt, libjade, formally verified ML-KEM |
| Karthikeyan Bhargavan / Franziskus Kiefer | Inria / Cryspen | hacspec, hax, libcrux (verified Rust ML-KEM) |
| Douglas Stebila / Thom Wiggers | Waterloo / PQShield | liboqs, OQS, KEMTLS, PQ protocol integration |
| Markku-Juhani O. Saarinen | Tampere / PQShield | ngcc.dev, hardware and side channels, standardization commentary |
| Thomas Prest / Thomas Pornin | PQShield / NCC | Falcon, masking, Raccoon; Pornin's experience with constant-time floating-point implementations |
| Prasanna Ravi / Shivam Bhasin / Anupam Chattopadhyay | NTU | Side-channel and fault attacks on lattice/code-based KEMs |
| Peter Pessl / Thomas Pöppelmann / Joppe Bos | Infineon / NXP | Embedded masking, single-trace attacks, industrial deployment |
| Filippo Valsorda / Sophie Schmieg / Bas Westerbaan | Geomys / Google / Cloudflare | Production deployment in Go/BoringSSL/Cloudflare, test vectors, TLS integration |
| Antoon Purnal | PQShield | Clangover, compiler-introduced leakage |

### 8.2 Must-read papers (by topic)

- **Software quality and standardization**: Kannwischer–Schwabe–Stebila–Wiggers, "Improving Software Quality in Cryptography Standardization Projects", SSR 2022 [ePrint 2022/337](https://eprint.iacr.org/2022/337); security analysis of KpqC first-round implementations [ePrint 2023/1437](https://eprint.iacr.org/2023/1437.pdf).
- **Timing leakage**: KyberSlash [ePrint 2024/1049](https://eprint.iacr.org/2024/1049); Guo–Johansson–Nilsson, FO timing attacks (CRYPTO 2020); Guo et al., timing attack on HQC fixed-weight sampling (TCHES 2022); timing-leakage toolchain for PQDSS candidates [arXiv 2509.04010](https://arxiv.org/pdf/2509.04010).
- **Polynomial multiplication**: Chung et al., "NTT Multiplication for NTT-unfriendly Rings" (TCHES 2021); Hwang et al., survey of vectorized polynomial multiplication from an algorithmic perspective; Seiler, AVX2 Kyber NTT (ePrint 2018/039).
- **Verification**: Almeida et al., the "Formally Verifying Kyber" series (Jasmin/EasyCrypt); Barbosa et al., "SoK: Computer-Aided Cryptography" (S&P 2021).
- **Masking**: Bos et al., "Masking Kyber" (TCHES 2021); del Pino et al., Raccoon.
- **Constant time from the developer's perspective**: Jancar et al. (S&P 2022).

### 8.3 Blogs and technical articles

- Filippo Valsorda: [Enough Polynomials and Linear Algebra to Implement Kyber](https://words.filippo.io/kyber-math/) (now with an ML-DSA appendix), [Accumulated Test Vectors](https://words.filippo.io/accumulated/).
- PQShield: [explanation of Clangover](https://pqshield.com/pqshield-plugs-timing-leaks-in-kyber-ml-kem-to-improve-pqc-implementation-maturity/), and other articles on implementation security.
- The [KyberSlash page](https://kyberslash.cr.yp.to/): tracks the fix status of each library. A textbook case of how far a vulnerability spreads downstream.
- Cloudflare blog (Bas Westerbaan and others): PQ-TLS deployment, middlebox compatibility, performance measurements.
- Project Eleven: [disclosure of the Threshold ML-DSA state-reuse issue](https://www.projecteleven.com/blog/nine-schemes-advance-to-round-3-of-nists-additional-digital-signatures-process).
- Giacomo Pope's [kyber-py](https://GitHub.com/GiacomoPope/kyber-py): a reference for how to write an "executable spec".

### 8.4 Slides, courses, and talks

- Peter Schwabe, [Kyber – Implementation aspects](https://cryptojedi.org/peter/data/cmmrs-20240801.pdf) (CMMRS 2024): includes step-by-step demonstrations of Clangover and table-lookup leakage. cryptojedi.org hosts many other PQC engineering lectures.
- Talks from the NIST PQC Standardization Conferences, e.g., [FIPS 206 FN-DSA progress](https://csrc.nist.gov/presentations/2025/fips-206-fn-dsa-falcon).
- PQC implementation and side-channel tutorials at Real World Crypto and CHES (recordings on YouTube).
- Materials from the PQCRYPTO summer school and the Summer School on Real-World Crypto and Privacy.

### 8.5 Forums and communities

- [NIST pqc-forum](https://groups.google.com/a/list.nist.gov/g/pqc-forum): the main place for discussing implementation issues. Recommended threads: [Clangover disclosure](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/hqbtIGFKIpU), [ML-KEM negative/intermediate/boundary test vectors](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/aCAX-2QrUFw/m/MuCObaS2AgAJ), [FIPS 206 status update](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/1HXzjlMUU6Y). Public comments on NGCC candidates have already appeared on this forum.
- The official ICCS NGCC public forums (two tracks) and the [ngcc-harness GitHub issues](https://github.com/ngcc-dev/ngcc-harness/issues).
- IETF CFRG / TLS / LAMPS mailing lists: decisions on encoding and protocol integration.
- GitHub Discussions of PQCA (Linux Foundation) and Open Quantum Safe.
- IACR ePrint: subscribe to the "Implementation" category.

## 9. NGCC Pre-Submission Checklist

Each item below corresponds to a problem reported against at least one candidate in the first-round public review. The ngcc.dev harness only covers reference implementations, so optimized versions such as AVX2 / Cortex-M4 need to run the same checks on their own.

**A. Security budget**

- [ ] For each parameter set, the lengths of seeds, hash outputs, challenges, salts, and shared keys are all ≥ the claimed security level (twice that for collision-related values), enforced with `_Static_assert`
- [ ] All length constants carry units in their names; check for bit/byte confusion
- [ ] The decryption-failure-rate analysis matches the actual implementation (including public-key rounding and compression error), backed by measured data

**B. KEM / FO**

- [ ] Bit-flipped ciphertexts: decapsulation outputs a deterministic pseudorandom key that differs from the correct key (a test program for this is in the [follow-up post](../crypto-informed-testing/), Section 9.2)
- [ ] The re-encryption comparison covers all ciphertext bytes and is constant time; the conditional copy covers all key bytes
- [ ] The KDF input for the rejection key binds the full ciphertext
- [ ] The decrypt→output path has no secret-dependent branches, divisions, or table lookups (compare with the "branch on decrypted coefficients" issue in kem-08-1)
- [ ] Public-key modulus check (or the spec explains why it is not needed)

**C. Signatures**

- [ ] Decode→re-encode is byte-for-byte equal, otherwise reject (padding bits, hints, high bits)
- [ ] Hint count/index range checks happen before any memory write
- [ ] All-zero, all-0xFF, truncated, and oversized signatures return an error without crashing
- [ ] Rejection-loop nonces never repeat and never wrap around

**D. Randomness and state**

- [ ] The KAT DRBG is linked only in test builds; the production path calls the system RNG and checks its return value
- [ ] Two consecutive keygen/encaps/ephemeral-key calls in the same process produce different outputs
- [ ] Protocol state cannot be reset or reused; identities and the transcript go into the KDF (KEX track)

**E. API and memory**

- [ ] Caller-declared lengths are compared against constants; return an error on mismatch (compare with the stack overflow in kem-14-1)
- [ ] Allocation failures and internal errors never return "success"; output buffers are zeroed on failure
- [ ] No `assert`/`abort` on external input
- [ ] Secret buffers are zeroed in a way that cannot be optimized away
- [ ] Remove debug paths, global secrets, and printf; review every file in the submission package

**F. Optimized implementations (AVX2 / AVX-512 / M4)**

- [ ] Each kernel is differentially tested against its reference function with random + extreme inputs (including out-of-range coefficients caused by malicious ciphertexts)
- [ ] The input/output range invariants of each kernel are written in comments and tested
- [ ] Tail reads/writes when n is not a multiple of the vector width are covered by ASan (note that alignment padding can hide out-of-bounds access)
- [ ] ref / AVX2 / M4 produce byte-for-byte identical outputs and return codes on the same set of malicious inputs
- [ ] M4: stack usage, hardware RNG, variable-latency multiply instructions

**G. Constant time and tooling**

- [ ] Valgrind secret-marking tests pass across the gcc/clang × `-O0`…`-O3`/`-Os` matrix
- [ ] KyberSlash-patched Valgrind checks for variable-latency instructions
- [ ] Publicly variable-time parts (e.g., rejection sampling on public seeds) are justified in the spec
- [ ] Parsing entry points are fuzzed continuously (decapsulation, verification, public-key import)

**H. Spec conformance**

- [ ] Independent executable spec + intermediate-value differential tests pass
- [ ] Every "must reject" in the spec has a negative test
- [ ] Public change log and errata; every fix comes with a regression test

We recommend mapping A–H onto the layers of your own test framework (baseline harness, differential testing against an independent model, general robustness suite) and running them in CI.

## Sources

- [ngcc.dev report index](https://ngcc.dev/reports/index.html) and [constant-time review](https://ngcc.dev/constant-time/index.html)
- [PostQuantum.com: NGCC first-round public findings](https://postquantum.com/security-pqc/china-ngcc-candidate-flaws/)
- [NIST: additional signatures Round 3 announcement](https://www.nist.gov/news-events/news/2026/05/nine-candidates-advance-third-round-additional-digital-signatures-pqc), [NIST IR 8610](https://csrc.nist.gov/pubs/ir/8610/final), [NIST IR 8240](https://nvlpubs.nist.gov/nistpubs/ir/2019/NIST.IR.8240.pdf)
- [PQClean](https://github.com/PQClean/PQClean), [ePrint 2022/337](https://eprint.iacr.org/2022/337), [ePrint 2023/1437](https://eprint.iacr.org/2023/1437.pdf)
- [KyberSlash ePrint 2024/1049](https://eprint.iacr.org/2024/1049), [Clangover](https://github.com/antoonpurnal/clangover), [Clangover pqc-forum disclosure](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/hqbtIGFKIpU)
- [C2SP CCTV ML-KEM vectors announcement](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/aCAX-2QrUFw/m/MuCObaS2AgAJ), [Accumulated Test Vectors](https://words.filippo.io/accumulated/)
- [Peter Schwabe: Kyber – Implementation aspects](https://cryptojedi.org/peter/data/cmmrs-20240801.pdf)
