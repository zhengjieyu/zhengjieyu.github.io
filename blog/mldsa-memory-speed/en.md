# ML-DSA on Small Chips: How Far Plain C Gets You on Memory, Code Size and Speed

*For anyone implementing post-quantum signatures on microcontrollers or embedded platforms · ~25 min read · October 30, 2026*

The ML-DSA (FIPS 204) reference implementation needs about 80 KB of stack for one signature. That is nothing on a server, but many microcontrollers have only 64 KB or 128 KB of SRAM in total. At the same time, many products cannot use assembly. They need portable C, for certification and for moving between platforms.

This post collects the known techniques from papers and open-source code into one list, in three parts: saving RAM, saving code size, and saving time. These three goals often conflict, so each technique comes with the price it costs. Some numbers come from small experiments I ran with the portable C backend of [mldsa-native](https://github.com/pq-code-package/mldsa-native) on an Apple M2. Use those for relative comparisons only. Cortex-M4 numbers come from [pqm4](https://github.com/mupq/pqm4).

## 1. First, Be Clear About What You Are Optimizing

| | RAM (stack/heap) | Code size (flash) | Speed |
| --- | --- | --- | --- |
| The question | How much data is alive at the deepest point of the run | How large are all the functions and constants linked into the firmware | How many cycles per operation |
| What counts | The **peak**, along the deepest call path only | The **sum** of everything that gets linked | Signing time varies with the number of rejection-sampling attempts |
| How to measure | Stack painting, `-fstack-usage` | `arm-none-eabi-size`, `nm --size-sort` | The DWT cycle counter, mean and maximum over many messages |

The three goals often conflict:

- Saving RAM usually means writing more code or computing the same thing again.
- Unrolling loops and using lookup tables for speed makes code bigger.
- Only changes that compile less in help both RAM and code size. Two examples are building a single parameter set and leaving out unused APIs.

### 1.1 Stack Painting

A microcontroller has no virtual memory. A stack overflow raises no error; it silently corrupts other variables. So the peak stack use has to be measured.

The usual method is stack painting:

1. Fill the whole stack with a known pattern.
2. Run the function.
3. Scan from the far end of the stack. The first word that changed marks the deepest point the function reached.

![Stack painting: fill the stack with a pattern, run the function, then scan up from the low end; the first changed word is the high-water mark, and the distance from the initial SP is the peak stack use](./diagrams/stack-painting.svg)

On bare metal it is only a few lines:

```c
extern uint32_t _sstack[], _estack[];   /* stack bounds from the linker script */
#define PAINT 0xA5A5A5A5u

void paint_stack(void) {
    uint32_t *p = _sstack, *sp;
    __asm volatile ("mov %0, sp" : "=r"(sp));
    while (p < sp - 16) *p++ = PAINT;        /* only paint below the current SP */
}

size_t stack_high_water(void) {
    uint32_t *p = _sstack;
    while (p < _estack && *p == PAINT) p++;
    return (size_t)((uint8_t *)_estack - (uint8_t *)p);
}
```

A few things to watch for:

- If interrupts share the stack, an interrupt during the measurement raises the mark.
- If the function happens to write the pattern value, the result is a few words too low.
- ML-DSA signing takes different paths because of rejection sampling. Measure over many messages and take the maximum.

Without a board, you can do the same in a thread with a fixed-size stack on a PC. The result is the right order of magnitude. GCC's `-Wstack-usage=N` complements painting: put it in CI to catch any single frame that grows too large.

## 2. Where the Memory Goes in ML-DSA Signing

Take ML-DSA-65, where the matrix is K = 6 by L = 5. A polynomial has 256 coefficients stored as `int32_t`, so it takes 1 KB.

| Object | Size | Notes |
| --- | --- | --- |
| Â, the public matrix in the NTT domain | 30 KB | Expanded from the 32-byte seed ρ with SHAKE128 |
| ŝ1, ŝ2, t̂0 | 17 KB | Secret vectors, unpacked from sk and moved to the NTT domain |
| y, w, w0, z, h | About 28 KB in total | Recomputed in every rejection-sampling attempt |
| sk, sig | 4032 B, 3309 B | Buffers the caller provides |

The diagram below lays these buffers out along the stages of signing. Each bar's height is proportional to the buffer's size. The total height of the solid blocks in a column is the memory that is alive at that moment.

![Lifetime of buffers in reference-style ML-DSA-65 signing: Â takes 30 KB and stays alive from expansion to the end; the peak is about 70 KB](./diagrams/lifetime-default.svg)

The dashed outlines show a problem specific to C. A local array in a function keeps its stack space from the moment the function is entered until it returns, whether or not it is still in use. So in C, shortening a lifetime has to be done in the code itself. Either put arrays that are used one after another in a `union`, or split the work into separate functions so that their stack frames do not overlap.

The diagram also suggests three directions:

- Â is the largest buffer, but it is fully determined by the 32-byte seed ρ, so it can be regenerated whenever it is needed.
- sk already holds a compact encoding of the secret vectors: s1 and s2 need only 3–4 bits per coefficient. They can be unpacked when they are used.
- The temporaries of one attempt are not all alive at the same time, so they can share space. Some do not need to be stored as whole vectors at all.

## 3. Saving RAM

The techniques in this section come mainly from three sources:

- [Greconici et al. (TCHES 2021)](https://eprint.iacr.org/2020/1278)
- [Bos, Renes and Sprenkels (AFRICACRYPT 2022)](https://eprint.iacr.org/2022/323), the approach behind pqm4's `m4fstack`
- mldsa-native's `MLD_CONFIG_REDUCE_RAM` option

| Technique | Saves (ML-DSA-65) | Cost |
| --- | --- | --- |
| **Generate Â on demand.** Generate one polynomial at a time and drop it after use. Going further, multiply-accumulate each coefficient into w as soon as SHAKE produces it, so no full polynomial is ever stored | 30 KB | Â is regenerated in every rejection attempt, so SHAKE128 work grows about 5× |
| **Store w in 24 bits.** All coefficients are below q < 2²³, so 3 bytes are enough | 6 KB → 4.5 KB | An extra pack/unpack on every access |
| **Don't store y.** Generate it once for w, then again from the same seed when computing z = y + c·s1 | 5 KB | L more SHAKE256 expansions per attempt |
| **Unpack s1, s2, t0 on demand.** Compute c·s1 and c·s2 with a 16-bit NTT modulo 769. Compute c·t0 by schoolbook multiplication, reading the packed t0 directly | 17 KB | A second, small NTT plus schoolbook code |
| **Compress c.** Store only the positions and signs of its non-zero coefficients | 1 KB → 68 B | Decompress before each use |
| **Reuse space.** Put the SHAKE128 and SHAKE256 states in one union. Use the signature buffer to hold the packed w1 before it is overwritten with the final signature | A few hundred bytes to a few KB | Almost none |

The small modulus is safe because the products are small. c has only τ non-zero ±1 coefficients and the coefficients of s1 are at most η in absolute value, so every coefficient of c·s1 is at most τ·η. For ML-DSA-65 that is 49 × 4 = 196, which is below 769/2. So the result modulo 769 is exactly the result modulo q.

With all of these applied, the same diagram at the same scale shrinks to a thin strip:

![Lifetime of buffers in low-stack ML-DSA-65 signing, at the same scale as above: only a 4.5 KB compressed w and one 1 KB temporary polynomial remain, about 6 KB in total](./diagrams/lifetime-lowstack.svg)

Verification can save memory the same way: compute w′1 one row at a time and absorb each row into SHAKE as soon as it is done. [Gonzalez et al. (PQCrypto 2021)](https://eprint.iacr.org/2021/662) go further and stream the public key and the signature themselves, targeting devices with 8 KB of RAM.

There is more than one way to balance verification:

- **The Linux kernel's verify-only code** ([`lib/crypto/mldsa.c`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/lib/crypto/mldsa.c)) generates Â one element at a time. It transforms ẑ to the NTT domain only once and keeps it, with a workspace of about 10 KB.
- **pqm4's `m4fstack`** goes down to 2.7 KB of stack. To get there, it redoes the NTT of z for every row, which makes verification about 2.4× slower.

If the signing key never changes, as with a device identity key, then Â never changes either. It can be computed in advance and stored in flash, and signing reads it instead of regenerating it. This recovers most of the speed while keeping RAM low. The cost is 16, 30 or 56 KB of flash for ML-DSA-44, 65 or 87.

The cost of saving memory falls almost entirely on signing:

![Three pqm4 ML-DSA-65 variants: clean uses 79.6 KB of stack and 12.4 million cycles, m4f uses 68.9 KB and 6.2 million, and m4fstack uses only 6.6 KB but 24.4 million cycles and the most code](./diagrams/tradeoff-m4.svg)

Each cell below gives stack peak · average cycles, where M means millions of cycles.

| ML-DSA-65 on Cortex-M4 (pqm4) | Keygen | Sign | Verify | Code (no hashing) |
| --- | --- | --- | --- | --- |
| clean (portable C) | 60.8 KB · 3.21 M | 79.6 KB · 12.36 M | 57.7 KB · 3.38 M | 7.7 KB |
| m4f (assembly) | 60.8 KB · 2.52 M | 68.9 KB · 6.19 M | 9.9 KB · 2.42 M | 19.3 KB |
| m4fstack (low stack) | 4.4 KB · 3.41 M | 6.6 KB · 24.42 M | 2.7 KB · 5.73 M | 24.1 KB |

Two patterns stand out:

- **The slowdown is concentrated in signing.** Key generation is only 35% slower, but signing is almost 4× slower. Only signing has the rejection-sampling loop, and every pass through it regenerates Â and y.
- **Going from 70 KB to about 15 KB is cheap; going further is expensive.** The first step needs only on-demand Â, borrowing from sk and unions. This is where mldsa-native's `REDUCE_RAM` stops. The second step needs the small NTT, schoolbook multiplication, coefficient-wise sampling and regenerating y.

## 4. Code Size: Why Saving Stack Makes Code Bigger

RAM is about the peak, and code size is about the sum, so the two pull in different directions. Almost every low-stack technique above adds code. The small NTT is a second NTT. Schoolbook is a second multiplication. Compressing w and c adds packing and unpacking functions. In pqm4, `m4fstack` has about 5 KB more code than the assembly `m4f`.

Common ways to control code size in plain C:

- **Build one parameter set and only the APIs you use.** A verify-only device can drop signing and key generation. mldsa-native has `MLD_CONFIG_PARAMETER_SET`, `MLD_CONFIG_CORE_API_ONLY`, `MLD_CONFIG_NO_SIGN_API` and similar options. wolfSSL has `WOLFSSL_MLDSA_VERIFY_ONLY`.
- **Ship one Keccak for the whole system.** ML-KEM, ML-DSA and SLH-DSA all use SHAKE and should share one implementation. In plain C there is no need for 4-way Keccak (mldsa-native's `MLD_CONFIG_SERIAL_FIPS202_ONLY`), and dropping it saves both code and RAM.
- **The way Keccak-f is written matters a lot.** Fully unrolling all 24 rounds adds several KB over a looped version, but runs faster.
- **Compiler flags.** Use `-Os`, `-ffunction-sections -fdata-sections -Wl,--gc-sections` and LTO as the baseline. Code built with `-O2` can be 2–4× larger than with `-Os`. Build only the hot files (Keccak, NTT) with `-O2` and the rest with `-Os`.
- **Measure after linking.** Object files still contain code that the linker would remove. Do not extrapolate from x86 either: on 32-bit Arm the hashing code is larger and the lattice code is smaller.

## 5. Where the Time Goes

Before speeding anything up, look at where a portable C implementation spends its time:

![Time breakdown of portable C ML-DSA-65: more than half of key generation and verification is Keccak, but only 29% of signing; the rest of signing is lattice arithmetic](./diagrams/time-breakdown.svg)

This matches earlier measurements:

- [Zheng et al.](https://arxiv.org/abs/2306.01989) profiled the Dilithium3 reference C code with `perf`. In signing, the Keccak permutation takes 38.8%, and `montgomery_reduce` alone takes 23.0%.
- pqm4 reports that hashing is 31% of signing for the portable C version on Cortex-M4. Once the lattice arithmetic is moved to assembly, hashing rises to 61%.

So speeding things up has two halves:

- For signing, cut the arithmetic inside the rejection-sampling loop.
- For key generation and verification, use a faster Keccak.

## 6. Speedup 1: Reorder the Rejection Checks

Each FIPS 204 signing attempt checks three things in order:

1. Is z too large?
2. Is r0 too large?
3. Are c·t0 and the hint h acceptable?

If any check fails, the attempt is discarded. The reference code follows this order: it computes all L polynomials of z first, then r0.

But the r0 check fails more often. The probabilities in [Zheng et al.](https://arxiv.org/abs/2306.01989) show that for ML-DSA-65, z passes with probability 0.62 and r0 only with 0.32. A signature is output only when all three checks pass, so changing their order does not change the signature. It only changes where a rejected attempt stops.

![Check order: in the FIPS 204 order, 38% of attempts are rejected at z and another 42% are rejected at r0 after z has already been computed; checking r0 first stops 69% of attempts before z is computed](./diagrams/check-order.svg)

I tried this on mldsa-native, which already checks each z polynomial as soon as it is computed and stops on the first failure. I moved the r0 computation and check in front of z and left everything else unchanged. Over 20,000 signatures:

- The number of attempts per signature did not change: 4.36, 5.18 and 3.94 for ML-DSA-44, 65 and 87.
- Signing became 4.4%, 7.6% and 5.9% faster.
- The signatures were byte-identical.
- The c·t0 check never rejected once in those 20,000 signatures.

The mldsa-native maintainers have also planned this change ([issue #1431](https://github.com/pq-code-package/mldsa-native/issues/1431)). Zheng et al. measured 2.1%–3.0% on the Round 3 reference code.

There are more aggressive ways to waste less work. They change the output of the signing algorithm: standard verifiers still accept the signatures, but signing no longer follows FIPS 204, so they are not usable when you need FIPS compliance or KAT tests:

- **Reusing the tail of y** ([Sprenkels and Westerbaan](https://eprint.iacr.org/2020/1158)). When the r0 check fails, only part of y is resampled. Signing is 11%–22% faster.
- **Pre-rejection sampling** ([Yan et al.](https://doi.org/10.1186/s42400-024-00325-6)). Keys are filtered during key generation, which cuts failures of the fourth check by 17%–47%. But signing is only about 1% faster, because the hint check almost never fails: in my count it rejected less than 0.01 times per signature.
- **wolfSSL's `WOLFSSL_MLDSA_SIGN_CHECK_Y` and `CHECK_W0` options.** They check y and w0 against a tighter range early. This wrongly rejects 1%–5% of attempts that would have been valid.

[Ravi et al.](https://eprint.iacr.org/2019/420) were early to study evaluating rejection conditions early and which intermediate values can be precomputed. They report speedups of 6%–35% on Intel and Cortex-M4.

## 7. Speedup 2: Cache the Expanded Key

Every signature makes the reference code redo two things that depend only on the key:

- expand Â with SHAKE128
- unpack s1, s2 and t0 and take their NTTs

If one key signs many times, these results can be cached. I added a test-only cache to mldsa-native: the first signature stores Â, ŝ1, ŝ2 and t̂0, and later signatures reuse them.

| Signing time (µs, Apple M2) | Default | Cached key | Cache + r0 first |
| --- | --- | --- | --- |
| ML-DSA-44 | 248 | 201 (−19%) | 191 (−23%) |
| ML-DSA-65 | 390 | 309 (−21%) | 280 (−28%) |
| ML-DSA-87 | 477 | 340 (−29%) | 311 (−35%) |

The cost is memory. ML-DSA-65 needs 30 KB for Â plus 17 KB for ŝ1, ŝ2 and t̂0, 47 KB in total, and ML-DSA-87 needs about 79 KB. That is exactly what Section 3 tries to remove, so caching directly conflicts with a low-memory goal. Also, ŝ1, ŝ2 and t̂0 are secrets: the cache needs the same protection as sk and must be zeroized after use.

Major libraries make different choices here:

- **BoringSSL** changed key generation in a [June 2026 commit](https://boringssl.googlesource.com/boringssl/+/ff43c4eb7f048a99c099201f3f058f0d0655a6fc) so that s1, s2 and t0 are stored in NTT form. Signing got 3.8%–8.5% faster and key generation 11%–16% slower. The commit argues that key generation needs s1 in NTT form anyway, so the total work is lower even for a key that signs only once.
- **Go's [`crypto/mldsa`](https://github.com/golang/go/blob/master/src/crypto/internal/fips140/mldsa/mldsa.go)** fully expands the private key (Â, ŝ1, ŝ2, t̂0, t̂1). It deliberately does not cache anything in the public key. A source comment explains that the public key would grow beyond 68 KB, and public keys are often used for a single verification while staying in memory for a long time, for example as a TLS peer certificate.
- **RustCrypto's [`ml-dsa`](https://github.com/RustCrypto/signatures/tree/master/ml-dsa)** precomputes for both keys. The public key caches Â and 2ᵈ·t̂1.
- **wolfSSL** leaves the choice to compile-time options: `WC_MLDSA_CACHE_MATRIX_A`, `WC_MLDSA_CACHE_PRIV_VECTORS` and `WC_MLDSA_CACHE_PUB_VECTORS`.
- **OpenSSL 3.5 and later** re-expands Â and transforms s1, s2 and t0 on every signature. It also computes all of z and r0 before checking either. On the same M2, its ML-DSA-65 signing takes about 552 µs against 399 µs for mldsa-native, while key generation and verification are close.

## 8. Speedup 3: How the Arithmetic Is Written in C

### 8.1 Let Small Functions Be Inlined

Montgomery reduction is only a few instructions, but the NTT and pointwise multiplication call it once per coefficient. The reference code keeps it in a separate `reduce.c`. Without LTO, the compiler cannot inline it across files. That is why it shows up as 23% of the profile.

I simulated this by building mldsa-native with `-fno-inline`. Signing went from 399 µs to 750 µs, 1.88× slower, and `montgomery_reduce` alone took 34% of the samples. The fix is to make such functions `static inline` in a header, to enable LTO, or to build everything as one translation unit as mldsa-native does.

### 8.2 Montgomery, Barrett, or a Precomputed Quotient

There are three common ways to multiply modulo q:

| Method | Used by | How it works | Output |
| --- | --- | --- | --- |
| Signed Montgomery | Reference code, mldsa-native, Linux kernel | t = a·q⁻¹ mod 2³², then (a − t·q) >> 32 | a·2⁻³² mod q in (−q, q); allows lazy reduction |
| Generic Barrett | RustCrypto (`module-lattice`) | quotient ≈ (x·⌊2⁴⁶/q⌋) >> 46, remainder = x − quotient·q, then one conditional subtraction | Fully reduced, [0, q) |
| Precomputed-quotient multiplication (Shoup / Barrett multiplication) | [Neon NTT](https://eprint.iacr.org/2021/986), mldsa-native's planned twisted zetas | For a fixed multiplier w, store w′ = ⌊w·2³²/q⌋; r = a·w − q·((a·w′) >> 32) | [0, 2q) |

RustCrypto's Barrett is simple and generic. The same macro serves ML-KEM and ML-DSA, the output is always fully reduced, and there are no bounds to track. The cost is that x·⌊2⁴⁶/q⌋ needs 70 bits, so it uses a 128-bit multiplication.

I wrote a microbenchmark and first checked all three against 2 million random pairs:

- **Apple M2, with auto-vectorization off:** 1.65 ns per multiplication for Barrett, 1.05 ns for Montgomery and 1.12 ns for the precomputed quotient. With vectorization on, the precomputed quotient drops to 0.19 ns and the other two barely change.
- **Cortex-M4, from the generated instructions:** the core of Montgomery is three instructions, `smull`, `muls` and `smlal`. Barrett needs `umull`, `umull` and `umlal` to build the 70-bit product, then shifts, a merge, an `mla` and a conditional subtraction: about 9–10 instructions. The M4 multiplies and multiply-accumulates in one cycle each, so by instruction count Montgomery is about 2.5× faster per reduction. This is an estimate, not a measurement on a board.

For the NTT, the multipliers are known twiddle factors, so the precomputed quotient is the best fit. The price is one extra stored value w′ per twiddle. mldsa-native plans to adopt it in its C code together with merging two NTT layers at a time ([issue #1118](https://github.com/pq-code-package/mldsa-native/issues/1118)).

### 8.3 Lazy Reduction

After each NTT layer, coefficients do not have to be reduced back into [0, q). They only have to stay within 32 bits. mldsa-native's C NTT works this way. The comments and CBMC contracts on each butterfly block state that the bound grows by q after the layer, and a formal tool proves that the whole NTT cannot overflow.

Go takes the opposite approach and reduces fully into [0, q) at every step. The code is simpler, at the cost of a few more reduction instructions. When writing your own version, the biggest risk is getting a bound wrong and overflowing. Either reuse bounds that have been proved, or add assertions and test them.

### 8.4 Smaller Changes

- **Decompose with one high multiplication instead of a two-step division** ([issue #1177](https://github.com/pq-code-package/mldsa-native/issues/1177)). For ML-DSA-65 and 87 this is `(a·1074791425 + 2⁴⁸) >> 49`.
- **CPUs with slow multipliers**, such as a Cortex-M0 with the 32-cycle multiplier. wolfSSL's `MLDSA_MUL_Q_SLOW` and `MLDSA_MUL_QINV_SLOW` replace multiplication by q and q⁻¹ with shifts and additions.
- **Plantard reduction.** [Huang et al.](https://tches.iacr.org/index.php/TCHES/article/view/11419) use it instead of Montgomery in 16-bit NTTs on Cortex-M3/M4. Their code is assembly. Whether C benefits the same way depends on whether the compiler emits the right instructions.

## 9. Speedup 4: Packed Small-Coefficient Multiplication Instead of the NTT

c·s1, c·s2 and c·t0 all multiply a sparse polynomial by a polynomial with small coefficients. c has only τ non-zero ±1 coefficients (τ = 49 for ML-DSA-65), and the coefficients of s1 and s2 lie in [−η, η]. The reference code still uses the NTT for these, with a full inverse NTT per polynomial.

[PSPM (parallel small polynomial multiplication), by Zheng et al. at ACSAC 2022](https://doi.org/10.1145/3564625.3564629), takes a different route. It packs the same coefficient of several polynomials into one 64-bit word. Each non-zero position of c then costs one add or subtract on the whole word.

![PSPM: coefficient i of five polynomials, 9 bits each, packed into one 64-bit word; each non-zero position of c is one word-sized add or subtract that processes all five products](./diagrams/pspm.svg)

This is SIMD inside a single register. It needs only integer adds and shifts, so plain C is enough.

- On the Round 3 reference C code, the paper reports signing 18%, 30% and 27% faster for Dilithium2, 3 and 5, and verification 19%, 7% and 3% faster.
- A [later improved version](https://arxiv.org/abs/2306.01989) adds early evaluation and gains another 5%–6% in signing.

The other common route on Cortex-M4 is a small-modulus NTT ([Abdulrahman et al., ACNS 2022](https://eprint.iacr.org/2022/112)). It runs a 16-bit NTT modulo 769 using the M4's 16-bit SIMD instructions, and makes the basemul plus inverse NTT in signing 33%–38% faster. That approach depends on assembly; under a plain C constraint, PSPM is the better fit.

## 10. Speedup 5: Keccak

More than half of key generation and verification is Keccak, so only a faster Keccak implementation helps there. The plain C options are:

| Implementation | Best for | Notes |
| --- | --- | --- |
| [XKCP](https://github.com/XKCP/XKCP/tree/master/lib/low/KeccakP-1600) `plain-64bits/KeccakP-1600-opt64.c` | 64-bit CPUs | Optional full unrolling and lane complementing; fast but large |
| XKCP `plain-32bits-inplace/KeccakP-1600-inplace32BI.c` | 32-bit MCUs | Bit interleaving: each 64-bit lane is split into its odd and even bits, so a 64-bit rotation becomes two 32-bit rotations |
| XKCP `compact/KeccakP-1600-compact64.c` | Smallest code | Written as loops; smallest and slowest |

Two more points:

- **On 32-bit platforms, absorb whole lanes.** [mldsa-native issue #450](https://github.com/pq-code-package/mldsa-native/issues/450) notes that with bit-interleaved Keccak on Armv7-M, XORing one lane into the state costs 37 extra instructions. If the input does not line up with a lane boundary, that cost is paid twice. When concatenating hash inputs, buffer them until a whole lane is full.
- **Even assembly helps only so much.** [Huang et al.](https://tches.iacr.org/index.php/TCHES/article/view/11419) made Keccak about 21% faster on Cortex-M4 with assembly. Hashing's share of total Dilithium time still dropped only by 2.46%–5.03%.

## 11. Compilers and Flags

The same mldsa-native code can differ by more than 2× in ML-DSA-65 signing time depending on the compiler and flags (Apple M2, µs):

| Configuration | Keygen | Sign | Verify |
| --- | --- | --- | --- |
| clang -Os | 179.8 | 511.7 | 158.8 |
| clang -O2 | 131.0 | 413.3 | 114.3 |
| clang -O3 | 127.6 | 398.8 | 109.2 |
| gcc-14 -Os | 207.1 | 545.4 | 182.1 |
| gcc-14 -O2 | 167.5 | 439.4 | 145.4 |
| gcc-14 -O3 | 158.4 | 365.5 | 133.9 |
| clang -O3, auto-vectorization off | 136.0 | 432.9 | 115.8 |
| clang -O3 -fno-inline | 158.5 | 749.7 | 169.4 |

What the table shows:

- **No compiler wins everywhere.** gcc -O3 signs fastest, but its key generation and verification are about 23% slower than clang's. Measure both compilers on your target.
- **`-Os` is 28%–49% slower than `-O3`.**
- **Auto-vectorization is worth about 8% on the M2.** The Cortex-M4 has no 128-bit SIMD, so this gain does not exist there.
- **Set `-mcpu=cortex-m4` on Cortex-M.** Otherwise the compiler may not use DSP instructions or hardware division.

## 12. Putting It Together

| Technique | RAM | Code | Signing speed | Output matches FIPS 204 |
| --- | --- | --- | --- | --- |
| One parameter set, trimmed APIs | Less | Less | Same | Yes |
| Serial Keccak, one copy for the whole system | Less | Less | About the same | Yes |
| Inlining small functions / LTO | Same | Slightly more | 1.9× slower without it | Yes |
| r0 check first | Same | About the same | 4%–8% faster | Yes |
| On-demand Â, borrowing sk, unions | 70 KB → about 15 KB | Same or slightly less | Signing about 1.9× slower (plain C) | Yes |
| Compressed w and c, resampled y, small NTT, schoolbook | About 15 KB → about 6 KB | About 5 KB more | About 4× slower than assembly in pqm4 | Yes |
| Cached expanded key (RAM or flash) | 47 KB more (ML-DSA-65) | Same | 19%–29% faster | Yes |
| PSPM | Same | Another multiplication routine | 18%–30% faster (Round 3 reference C) | Yes |
| Reusing the tail of y, early range checks | — | — | 11%–22% faster | No |

For a device that is tight on both RAM and code space, a reasonable order is:

1. **Start with the free wins.** Make sure the reduction functions get inlined. Build one parameter set. Use serial Keccak. Check r0 before z. None of these adds RAM or changes the output.
2. **Pick a RAM tier.** If a dozen or so KB of stack is acceptable, stop at the on-demand Â tier, such as mldsa-native's `REDUCE_RAM`; code does not grow. Go down to 6 KB only if RAM really requires it.
3. **For fixed keys, consider caching.** Storing Â in flash trades flash for speed, if the flash budget allows.
4. **Leave the code-heavy work for last.** PSPM and a 32-bit-friendly Keccak pay off, but both add code.

After each change, measure all three: stack with painting, code size with `size` on the linked binary, and speed with the cycle counter over many messages, both mean and maximum.

## Sources

- Greconici, Kannwischer, Sprenkels, "Compact Dilithium Implementations on Cortex-M3 and Cortex-M4", TCHES 2021(1), [ePrint 2020/1278](https://eprint.iacr.org/2020/1278)
- Bos, Renes, Sprenkels, "Dilithium for Memory Constrained Devices", AFRICACRYPT 2022, [ePrint 2022/323](https://eprint.iacr.org/2022/323)
- Gonzalez, Hülsing, Kannwischer et al., "Verifying Post-Quantum Signatures in 8 kB of RAM", PQCrypto 2021, [ePrint 2021/662](https://eprint.iacr.org/2021/662)
- Abdulrahman, Hwang, Kannwischer, Sprenkels, "Faster Kyber and Dilithium on the Cortex-M4", ACNS 2022, [ePrint 2022/112](https://eprint.iacr.org/2022/112)
- Huang et al., "Revisiting Keccak and Dilithium Implementations on ARMv7-M", [TCHES 2024(2)](https://tches.iacr.org/index.php/TCHES/article/view/11419)
- Becker, Hwang, Kannwischer, Yang, Yang, "Neon NTT: Faster Dilithium, Kyber, and Saber on Cortex-A72 and Apple M1", TCHES 2022(1), [ePrint 2021/986](https://eprint.iacr.org/2021/986)
- Ravi, Sen Gupta, Chattopadhyay, Bhasin, "Improving Speed of Dilithium's Signing Procedure", [ePrint 2019/420](https://eprint.iacr.org/2019/420)
- Sprenkels, Westerbaan, "Don't throw your nonces out with the bathwater", [ePrint 2020/1158](https://eprint.iacr.org/2020/1158)
- Yan, Luo, Wang, "Speedup signing: pre-rejection sampling towards Dilithium", [Cybersecurity 2025](https://doi.org/10.1186/s42400-024-00325-6)
- Zheng, He, Shen, Xue, Zhao, "Parallel Small Polynomial Multiplication for Dilithium: A Faster Design and Implementation", [ACSAC 2022](https://doi.org/10.1145/3564625.3564629)
- Zheng, Zhu, Song, Wang, Zhao, "Optimized Vectorization Implementation of CRYSTALS-Dilithium", [arXiv:2306.01989](https://arxiv.org/abs/2306.01989)
- [pqm4 benchmarks](https://github.com/mupq/pqm4/blob/master/benchmarks.md), `crypto_sign/ml-dsa-*/{clean,m4f,m4fstack}`
- [mldsa-native](https://github.com/pq-code-package/mldsa-native) and issues [#1431](https://github.com/pq-code-package/mldsa-native/issues/1431), [#1118](https://github.com/pq-code-package/mldsa-native/issues/1118), [#1177](https://github.com/pq-code-package/mldsa-native/issues/1177), [#450](https://github.com/pq-code-package/mldsa-native/issues/450)
- The build options documented at the top of [wolfSSL `wc_mldsa.c`](https://github.com/wolfSSL/wolfssl/blob/master/wolfcrypt/src/wc_mldsa.c)
- [BoringSSL commit ff43c4e: Store ML-DSA's s1, s2, and t0 in NTT form](https://boringssl.googlesource.com/boringssl/+/ff43c4eb7f048a99c099201f3f058f0d0655a6fc)
- [Go `crypto/internal/fips140/mldsa`](https://github.com/golang/go/tree/master/src/crypto/internal/fips140/mldsa)
- [RustCrypto `ml-dsa`](https://github.com/RustCrypto/signatures/tree/master/ml-dsa) and [`module-lattice`](https://github.com/RustCrypto/KEMs/tree/master/module-lattice)
- [OpenSSL `crypto/ml_dsa/ml_dsa_sign.c`](https://github.com/openssl/openssl/blob/master/crypto/ml_dsa/ml_dsa_sign.c)
- [Linux `lib/crypto/mldsa.c`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/lib/crypto/mldsa.c)
- [XKCP KeccakP-1600 implementations](https://github.com/XKCP/XKCP/tree/master/lib/low/KeccakP-1600)
- Numbers marked Apple M2 use mldsa-native (commit 33031ee) with its portable C backend, built with clang 14 or gcc 14, taking the mean of the fastest of three runs. OpenSSL numbers come from `openssl speed` (3.6.3).
