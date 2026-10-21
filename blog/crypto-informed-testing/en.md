# Flip One Bit: What Cryptographically-Informed Testing Finds in PQC Implementations

*Paper notes for cryptographic engineers · ~35 min read · October 21, 2026*

Known-answer tests (KATs) check that an implementation produces the same outputs as the reference implementation on a fixed list of about a hundred inputs. Sanitizers such as AddressSanitizer check that it does not read or write memory it does not own. Neither check tells you that `Decaps` (the decapsulation function of a key encapsulation mechanism, or KEM) returned the original key for a ciphertext it should have rejected. Neither tells you that `Verify` accepted a signature with extra bytes appended. These bugs do not crash the program. They break a security property without any visible error.

This post covers a TCHES 2026 paper by Giacomo Fenzi, Jan Gilcher, and Fernando Virdia. The paper turns security definitions into test programs that crash when the property fails. I go through the method and then the findings, from the point of view of someone who writes implementations: what broke, why it broke, and which check in your own code would have caught it.

> **In one sentence:** take a valid input, flip one bit, and check that the output changes when it must change and stays the same when it must not. Written once as a generic test program, this finds IND-CCA breaks, strong-unforgeability breaks, out-of-bounds reads, and several unexpected properties that ordinary fuzzing does not detect.

## 0. Overview

The main conclusions first. A few terms are used throughout, so they are defined here:

- **Fuzzing** runs a program on many automatically generated inputs and records crashes. **AFL++** is a widely used fuzzer.
- **IND-CCA** is the standard security notion for KEMs: an attacker who can ask for the decapsulation of any ciphertext except the challenge ciphertext still cannot learn anything about the challenge key.
- **sUF-CMA** (strong unforgeability) is a security notion for signatures: after seeing valid signatures, an attacker cannot produce any new valid message–signature pair, not even a second signature for a message that was already signed.
- **Malleability** in this post means that an input was changed and the output stayed the same.

The conclusions:

1. **The bugs that matter most for security do not crash.** LibOQS is the C library of post-quantum schemes maintained by the Open Quantum Safe project. On LibOQS 0.8.0 and 0.14.0, a conventional AFL++ campaign found nothing. The tests from this paper found 2 and 25 strong-unforgeability counterexamples on the same versions. Across all versions, the conventional campaign missed 13 IND-CCA and 36 sUF-CMA counterexamples.
2. **Most real findings are non-canonical encodings.** An encoding is non-canonical if more than one byte string decodes to the same value. NTRU did not check the padding bits of its ciphertext. Falcon accepted "−0" and non-zero padding. SNOVA accepted any value in unused trailing bits. CROSS ignored the signature length. All four are the same kind of bug.
3. **The method is cheap.** It needs four functions (`GenInput`, `Call`, `Maul`, `Match`), a format string that labels each input bit as "must affect the output" or "must not affect the output", one guard byte on each side of the input buffer, and AFL++ to run the tests in parallel. One LibOQS version takes about half a day on 31 to 75 cores.
4. **Some findings are not bugs, and the paper says so.** Most KEMs use the Fujisaki–Okamoto (FO) transform to reach IND-CCA security. In its "implicit rejection" form, part of the secret key is unused when the ciphertext is valid. Randomized Dilithium ignores part of its secret key. Some public keys can be modified without breaking verification. None of this violates IND-CCA or EUF-CMA (the weaker, standard unforgeability notion), but a protocol that assumes otherwise can fail.
5. **It adds to ordinary fuzzing and does not replace it.** The conventional campaign caught two crashes that the new method missed (Dilithium III aborts, Picnic_L3_UR segmentation faults), because the new method always starts from one fixed valid input.

Suggested reading path:

1. Sections 1–3 explain why ordinary testing misses these bugs and how a security notion becomes a test predicate. Skip them if you know metamorphic testing.
2. Sections 4–6 are the framework and the 13 tests. Read them if you want to build your own harness.
3. Sections 7–11 are the experiments and case studies. Section 9 is the part most worth reading for implementers.
4. Sections 12–15 are my assessment, a mapping to the NGCC first-round findings, a harness sketch you can adapt, and a checklist.

Note: this post is a reading of the paper ([TCHES 2026(1), pp. 425–447](https://doi.org/10.46586/tches.v2026.i1.425-447), [ePrint 2024/1122](https://eprint.iacr.org/2024/1122), [code](https://github.com/jangilcher/cryptoTesting)). Links marked [source] were checked while writing. Paragraphs marked *my reading* are my interpretation rather than claims made in the paper. Please verify against the original before citing.

## 1. Why ordinary tests miss these bugs

A new implementation `P` of a primitive is usually tested in one of two ways. Either it reproduces known-answer vectors, or it is compared against a reference implementation `P0` on random inputs. This second method is called differential testing. Both assume `P0` is correct. Nobody tests `P0` itself, because its output is designed to look random: given `t` and `P0(t)`, there is no way to tell whether `P0(t)` is right. For a hash function it is harder still, since there is no inverse to check against. Software testing calls this the **oracle problem** (Weyuker, 1982). Here, a test oracle is any procedure that decides whether an output is correct.

This matters because reference implementations are reused. They generate the KATs that every later implementation is checked against, and they are sometimes shipped directly. The paper opens with two examples of what happens when a "secure on paper" scheme meets an incorrect implementation: the "psychic signatures" bug in Java's ECDSA ([CVE-2022-21449](https://www.cve.org/CVERecord?id=CVE-2022-21449)) and the buffer overflow in the Keccak reference code ([CVE-2022-37454](https://www.cve.org/CVERecord?id=CVE-2022-37454)).

Fuzzing helps, but only with bugs that show up as crashes. A coverage-guided fuzzer such as AFL++ mutates inputs and keeps those that reach new code paths; it reports an input when the program crashes, hangs, or fails an assertion. The table lists what each kind of test can detect:

| Test layer | What it observes | What it cannot see |
|---|---|---|
| KAT | Output on ~100 DRBG-generated inputs equals the reference | Behavior on any malformed or adversarial input |
| Differential vs. reference | Agreement with `P0` on random inputs | Bugs that `P0` shares |
| Sanitizers (ASan/UBSan/MSan) | Access to unallocated memory, UB | Reads of *adjacent valid* memory; any logical flaw |
| Coverage-guided fuzzing | Crashes, hangs, assertion failures | A `Decaps` that returns the right key for a tampered ciphertext |
| **Cryptographically-informed tests** | **Violations of a stated input/output relation** | Bugs that need structured, multi-bit inputs (see Section 12) |

The fourth row is the gap this paper fills. A KEM that decapsulates a tampered ciphertext to the original key runs without any error. So does a hash function that ignores one input bit. To see either, the test program has to know what the primitive is supposed to guarantee.

## 2. Background: metamorphic testing and Mouha et al.

**Metamorphic testing** (Chen, Cheung, Yiu; Zhou et al.) sidesteps the oracle problem. You cannot say whether one output is correct, but you can often say how *two* outputs must relate. A test case is *indeterminate* if it does not obviously fail; a *metamorphic relation* transforms indeterminate cases into pairs that can be classified as failures. For a hash function: you do not know what `H(x)` should be, but you know that `H(x)` and `H(x ⊕ e_i)` must differ.

The paper builds on Mouha, Raunak, Kuhn, and Kacker (IEEE Transactions on Reliability, 2018), who ran a post-mortem on 86 SHA-3 competition reference implementations with three such relations:

| Test | Relation | A failure means | Failed / 86 |
|---|---|---|---|
| **Bit-Contribution** | Flip each bit of an input of length ℓ; all hashes must be distinct | Some input bit does not reach the output | 19 |
| **Bit-Exclusion** | SHA-3 had to support bit lengths not divisible by 8. For ℓ ≡ 6 (mod 8), flip the 2 unused bits of the last byte; hashes must be *equal* | The implementation reads bits that are not part of the message | 17 |
| **Update** | `Hash(x) = Final ∘ Update(ℓ2) ∘ Update(ℓ1) ∘ Init(x)` for ℓ1 + ℓ2 = \|x\| | The streaming API is inconsistent with one-shot hashing | 32 |

Two of the five SHA-3 finalists had such bugs. None of these tests needs a specification beyond "a hash should be second-preimage resistant" and "unused bits are unused".

## 3. Security notions as test predicates

The step from Mouha et al. to KEMs and signatures is to notice that each security game has a cheap, concrete counterexample shape. You do not need a clever adversary. You need one input pair that the game says should be impossible.

| Notion | Game in one line | One counterexample is enough | Which test finds it |
|---|---|---|---|
| Second-preimage resistance | Given random `x`, find `x' ≠ x` with `H(x') = H(x)` | `x' = x ⊕ e_i` hashes to the same digest | Test 1 |
| **IND-CCA** (KEM) | Distinguish `ss*` from random, with a decapsulation oracle that refuses only `c*` | `c' = c* ⊕ e_i` decapsulates to `ss*`. Submit `c'`, compare with the challenge, win with probability 1 | Test 7 |
| **sUF-CMA** (signature) | After seeing signatures, output a *new* valid pair `(m*, σ*)`, where new means the pair was never returned | `σ' = σ ⊕ e_i` (or `σ` with a different length) still verifies for `m` | Test 13 |
| EUF-CMA | As sUF-CMA but `m*` must be a new message | Not testable by single bit flips; the tests do not claim to | none |

The IND-CCA row is worth spelling out. In the game, the adversary gets `c*` and a key that is either `ss*` or random, plus an oracle that decapsulates anything except `c*`. If flipping one bit of `c*` gives a ciphertext that still decapsulates to `ss*`, the adversary queries the oracle on `c'`, gets `ss*`, and compares. The scheme is broken outright, not with some small advantage. That is why a single successful Test 7 counterexample on a scheme claiming IND-CCA is a real bug.

The sUF-CMA row is subtler. NIST did not require strong unforgeability, and many candidates do not claim it. But some constructions *imply* it (the GPV hash-and-sign framework of Gentry, Peikert, and Vaikuntanathan, which Falcon uses), and some protocols rely on it, for example when a signature is used as a unique identifier of a transaction or message. A violation is a bug if the scheme claims the property or its construction should provide it, and a hazard otherwise.

## 4. From hashes to KEMs and signatures

Moving the idea to KEMs and signatures brings more to test and four practical differences.

**More functions, with structure between them.** A hash has one function. A KEM has `(Gen, Encaps, Decaps)` and a signature scheme has `(Gen, Sign, Verify)`. They compose: "encapsulate under a tampered public key, then decapsulate with the original secret key" is a meaningful relation that a hash cannot offer.

**Randomness.** `Gen`, `Encaps`, and `Sign` consume a random tape, which is the sequence of random bytes the algorithm reads. In the tests, these bytes come from a pseudorandom generator (PRG) started from a seed. The paper handles randomness in two ways:

- When tampering with a *different* input (say, `pk` in `Encaps`), fix the PRG seed so that runs are reproducible.
- When tampering with the *random tape itself*, changing the seed would only test a different random input. Instead they install a **bad PRG that outputs one fixed byte forever**, and iterate that byte over 0…255. This is outside every security model, but it exposes implementations that loop forever when the random tape is unlucky, for example key generation that keeps rejecting candidates. LibOQS supports a custom RNG, so this is easy to wire in.

**Mostly fixed-length inputs.** Unlike hashes, KEM and signature inputs mostly have fixed lengths. The exceptions are random tapes (handled through fixed-length seeds), messages (fixed, because messages are hashed first and testing their lengths would only test the hash), and variable-length signatures. For the last, the signature lives in a buffer large enough for the longest signature, next to a field holding its byte length `ℓσ`, and **both `σ` and `ℓσ` are tampered with**. This detail catches CROSS (Section 9.6).

**Return values.** Textbook syntax for KEMs and signatures has no return codes. Implementations use them heavily: `Verify` returns accept/reject, and several KEMs signal explicit rejection through the return value. The paper treats the return value `rv` as part of every output, so `Gen` returns `(pk, sk, rv)`. A footnote points out that the LibOQS documentation says return values only report unexpected errors, which does not match what the code does.

NIST also did not mandate an internal API for PQC submissions, so there is no counterpart of the Update test.

## 5. The framework: four functions and one loop

The engineering goal is that a library maintainer can adopt these tests with little effort. So the paper defines a **metamorphic test specification** as four functions, `Φ = (GenInput, Call, Maul, Match)`:

| Function | Signature | Role |
|---|---|---|
| `GenInput` | `(Π, pp, fmt) → (x, y, aux)` | Produce a valid input `x`, its baseline output `y`, and data `aux` that is not tampered with (e.g. `sk` when tampering with `c`) |
| `Call` | `(Π, x, aux, pp, fmt) → y` | Run the method under test |
| `Maul` | `(x, fmt, σ) → (x', σ', expected)` | Produce the next tampered input and say whether the output should be *equal* or *different* |
| `Match` | `(y, y', expected) → ok / abort` | Compare, and crash on an unexpected result |

![The Test loop: GenInput produces a baseline, Maul flips one bit and states the expectation, Call reruns the function, Match aborts on a mismatch, and AFL++ stores the crashing input](./diagrams/test-loop.svg)

The driver is a plain fuzzing loop:

```text
Test(Π, pp, fmt, runs, σ0):
  sus ← []; σ ← σ0
  (x, y, aux) ← GenInput(Π, pp, fmt)
  for i in 1..runs:
      (x', σ', expected) ← Maul(x, fmt, σ);  σ ← σ'
      try:
          y' ← Call(Π, x', aux, pp, fmt)
          Match(y, y', expected)          # aborts on mismatch
      catch:
          sus.append((x, fmt, σ))
  return sus
```

There is exactly one `Match` in the whole paper: two outputs `(d, rv)` and `(d', rv')` are equal if both the data and the return value are equal, and the test aborts if that equality differs from the expectation. Because `Match` and most of `Maul` do not depend on the primitive, they are reused unchanged; `Call` and `GenInput` share most of their structure across tests.

One deliberate difference from Mouha et al.: the loop compares **one pair** `(y, y')` at a time, rather than collecting many outputs and searching for collisions. The reason is practical. A pairwise check can be written as an AFL++ custom mutator (a user-supplied function that AFL++ calls to produce the next input), so the tests can reuse AFL++'s parallel execution, crash storage, and crash reproduction. When `Match` aborts, AFL++ records it as a crash.

The paper is explicit that the formal framework only normalizes terminology. The contribution is the set of **cryptographically-informed programs to fuzz**: programs that crash exactly when a cryptographic property fails.

### 5.1 Types

The C implementation mirrors `Φ` with a few abstract types:

| Type | Meaning | Contents |
|---|---|---|
| `in_t` | input `x` | pointer to a byte buffer + byte length |
| `out_t` | output `y` | byte buffer + length + integer return value |
| `aux_t` | auxiliary data | list of byte buffers with lengths |
| `pp_t` | public parameters | for LibOQS, just the algorithm identifier |
| `fmt_t` | format string | list of `(bit length, label)` |
| `exp_res_t` | expectation | boolean: outputs should match or not |

### 5.2 Format strings and guard bytes

This is the most useful idea in the paper. A format string is a list of `(ℓ, label)` pairs, where the label is `DIFF` (flipping a bit here must change the output) or `EQ` (flipping a bit here must not). One format string expresses bit-contribution and bit-exclusion at once.

The paper's example is a 14-bit hash input stored in two bytes, so the last two bits of the second byte are not part of the message. With one guard byte on each side:

```text
fmt = [(8, EQ), (14, DIFF), (2, EQ), (8, EQ)]
```

The test passes `&x[1]` to the function under test, never `&x[0]`. The guard bytes are initialized to `0xFF`. Flipping any message bit must change the digest. Flipping one of the two padding bits, or any bit of either guard byte, must not. If it does, the implementation is reading memory outside its input.

Every KEM and signature test in the paper uses the same shape: `[(8, EQ), (|input|, DIFF), (8, EQ)]`.

![Test 7 buffer layout: a guard byte, the ciphertext marked DIFF including the last byte's padding bits, and a trailing guard byte; flipping the guard must leave the output unchanged, flipping any ciphertext bit must change it](./diagrams/buffer-layout.svg)

*My reading:* the guard bytes catch a class of bug that sanitizers miss. ASan reports reads of unallocated or poisoned memory. A read of the next byte of a larger, valid allocation is invisible to it, and that is what KNOT-384 did (Section 9.2).

### 5.3 The Maul schedule

Most tests share one `Maul` (Figure 4 of the paper). Its state `σ` starts at −3:

| σ | Tampered input | Expected |
|---|---|---|
| −3 | unchanged | equal (is the function deterministic under a fixed seed?) |
| −2 | whole buffer set to all zeros | different, if any `DIFF` byte changed |
| −1 | whole buffer set to all ones | different, if any `DIFF` byte changed |
| 0, 1, 2, … | flip bit σ | by the label of the region containing bit σ |

Tests that tamper with the random tape (Tests 2, 5, 10) use a simpler `Maul`: the bad PRG repeats one byte, `σ` is that byte, it runs from 0 to 255, and each value must give a different output.

## 6. The thirteen tests

| # | Call under test | Tampered input | Must hold | Report name in the code |
|---|---|---|---|---|
| 1 | `Hash(Maul(x))` | message + guards | digest changes iff a message bit changes | (SUPERCOP) |
| 2 | `Gen(; Maul(r))` | random tape | different tapes give different keys; no hang | `KEM/Keygen/badrng`, `SIGN/Keygen/badrng` |
| 3 | `Encaps(Maul(pk); r)` | public key | `(ss, c)` changes | `KEM/Encaps/pk-0` |
| 4 | `Decaps(sk, Encaps(Maul(pk); r))` | public key | decapsulating under the original `sk` must not give the same key | `KEM/Encaps/pk` |
| 5 | `Encaps(pk; Maul(r))` | random tape | `(ss, c)` changes | `KEM/Encaps/badrng` |
| 6 | `Decaps(Maul(sk), c)` | secret key | shared secret changes | `KEM/Decaps/sk` |
| 7 | `Decaps(sk, Maul(c))` | ciphertext | shared secret changes (**IND-CCA**) | `KEM/Decaps/c` |
| 8 | `Sign(Maul(sk), m; r)` | secret key | signature changes | `SIGN/Sign/sk` |
| 9 | `Sign(sk, Maul(m); r)` | message | signature changes | `SIGN/Sign/m` |
| 10 | `Sign(sk, m; Maul(r))` | random tape | signature changes (deterministic schemes are expected to collide) | `SIGN/Sign/badrng` |
| 11 | `Verify(Maul(pk), m, σ)` | public key | verification fails | `SIGN/Verify/pk` |
| 12 | `Verify(pk, Maul(m), σ)` | message | verification fails | `SIGN/Verify/m` |
| 13 | `Verify(pk, m, Maul(σ))` | signature and its length | verification fails (**sUF-CMA**) | `SIGN/Verify/sig` |

The report names come from the [repository README](https://github.com/jangilcher/cryptoTesting) [source], which is useful if you read the generated reports.

A few tests deserve a closer look.

- **Test 4** composes two functions. It encapsulates under a tampered `pk'`, then decapsulates the result with the *original* `sk`, and checks that the two shared secrets differ. A collision means some bits of `pk` never influence what the ciphertext commits to.
- **Test 6** is where FO implicit rejection shows up (Section 10.1). Expect many hits on correct implementations.
- **Test 10** inverts the expectation for deterministic schemes: changing the random tape *should not* change a deterministic signature, so collisions there are fine.
- **Test 13** uses its own `Maul` with format `[(|ℓσ|, DIFF), (8, EQ), (|σ|, DIFF), (8, EQ)]`. It first sets the length field to each value smaller than the true length, then flips each bit of the signature. A scheme that ignores the length passes verification for a truncated length, which is how CROSS was caught.

## 7. Experimental setup

**Hardware.**

| Machine | CPU | Cores | RAM |
|---|---|---|---|
| A | 2 × Intel Xeon Gold 6138, 2.00 GHz | 40 | 376 GiB |
| B | 4 × Intel Xeon Gold 6252, 2.10 GHz | 96 | 754 GiB |
| C | 1 × AMD EPYC 7742, 2.25 GHz | 64 | 503 GiB |

**AFL++ configuration.** Three changes to the defaults:

- The input size limit was raised from 1 MB to 10 MB, because some public keys are very large.
- All built-in mutators were disabled and replaced with a single custom bit-flip mutator. AFL++ cannot disable individual built-in mutators, so a custom mutator is the only way.
- At most 10 unique crashes are stored per target, to avoid terabytes of output.

The authors say plainly that AFL++ is used mainly for crash handling and storage, and that other fuzzers would do. *My reading:* with the mutators replaced by a deterministic schedule, AFL++ acts as a parallel test runner. Coverage guidance plays essentially no role.

**Targets.**

- LibOQS 0.14.0 (July 2025), 0.8.0 (June 2023), 0.4.0 (August 2020), and the `nist-branch` snapshot of November 2018.
- Hash functions in SUPERCOP 20240107. SUPERCOP is a benchmarking suite that collects many implementations behind one API.

Why old versions? LibOQS removes schemes as they drop out of the NIST process, so testing only the newest version would cover few schemes. Together the four snapshots include most reference implementations submitted to NIST PQC. The authors argue that automated testing should be applied early, so testing immature code is the point.

**Baseline.** A set of AFL++ harnesses with no semantic knowledge: they parse a binary file into the function's inputs and enforce the right lengths for fixed-length inputs. Key generation takes no direct input, so the baseline does not cover `Gen`.

**Counting rule.** Results are counted per (scheme, parameter set, LibOQS version), and multiple triggering inputs within one combination count once. If one line of code triggers a bug in `XYZ-128` and `XYZ-256` in both 0.4.0 and 0.8.0, that counts four times. The counting is automatic, without manual root-causing. So the totals measure *affected combinations*, not *distinct bugs*.

## 8. Results at a glance

### 8.1 Baseline crashes and hangs

| Library | KEM Encaps | KEM Decaps | DSS Sign | DSS Verify | Wall time | Machine (cores) |
|---|---|---|---|---|---|---|
| LibOQS 0.14.0 | 0 | 0 | 0 | 0 | 2h | A (31) |
| LibOQS 0.8.0 | 0 | 0 | 0 | 0 | 27m | C (50) |
| LibOQS 0.4.0 | 8 | 0 | 9 (1 hang) | 0 | 57m | C (50) |
| LibOQS nist-branch 2018-11 | 10 | 12 (1 hang) | 5 | — | 23m | B (75) |
| SUPERCOP 20240107 (hash) | 4 | | | | 8h 6m | C (50) |

KEM crashes fall from the oldest version to 0.4.0: every crash in `nist-branch` is gone in 0.4.0, and the 0.4.0 crashes are all in schemes that did not exist in `nist-branch`. Signature crashes rise in 0.4.0, apparently a regression in several Picnic variants. From 0.8.0 on, ordinary fuzzing finds nothing.

### 8.2 Cost of the cryptographically-informed tests

| Library | Wall time | Machine (cores) |
|---|---|---|
| LibOQS 0.14.0 | 12h 40m | B (75) |
| LibOQS 0.8.0 | 14h 23m | A (31) |
| LibOQS 0.4.0 | 12h 43m | A (31) |
| LibOQS nist-branch 2018-11 | 8h 59m | A (31) |
| SUPERCOP 20240107 | 6h 58m | A (31) |

Half a day per library. For a standardization project or a large library, that fits a nightly or weekly job.

### 8.3 Totals

- **200+ malleabilities**: changing one input did not change the output.
- **48 hangs, 50 segmentation faults, 3 heap overflows, 2 stack overflows** triggered by tampering with an intended input.

Not every malleability is a bug (Section 10). The memory errors could be vulnerabilities, depending on how exposed the API is.

### 8.4 Per-test results (Table 3 of the paper)

"Mall." counts bit-contribution failures (output did not change). "Non-mall." counts bit-exclusion failures (output changed when it should not have). Tests with no results are omitted.

**SUPERCOP 20240107**

| Test | Mall. | Crash/hang | Non-mall. |
|---|---|---|---|
| 1 | 3 | 0 | 3 |

**LibOQS 0.14.0 (07/2025)**

| Test | Mall. | Crash/hang | Non-mall. |
|---|---|---|---|
| 5 | 1 | 10 (hang) | 0 |
| 6 | 26 | 0 | 0 |
| 8 | 11 | 0 | 0 |
| 11 | 10 | 0 | 0 |
| 13 | 25 | 0 | 0 |

**LibOQS 0.8.0 (06/2023)**

| Test | Mall. | Crash/hang | Non-mall. |
|---|---|---|---|
| 3 | 10 | 0 | 0 |
| 4 | 10 | 0 | 0 |
| 5 | 1 | 10 (hang) | 0 |
| 6 | 23 | 0 | 0 |
| 8 | 3 | 0 | 0 |
| 13 | 2 | 0 | 0 |

**LibOQS 0.4.0 (08/2020)**

| Test | Mall. | Crash/hang | Non-mall. |
|---|---|---|---|
| 3 | 23 | 8 (segf.) | 0 |
| 4 | 31 | 8 (segf.) | 0 |
| 5 | 1 | 10 (hang) | 0 |
| 6 | 51 | 0 | 0 |
| 7 | 10 | 0 | 0 |
| 8 | 10 | 3 (heap overf.) + 1 (hang) | 0 |
| 9 | 0 | 1 (hang) | 0 |
| 10 | 22 | 1 (hang) | 0 |
| 11 | 7 | 1 (hang) | 0 |
| 12 | 0 | 1 (hang) | 0 |
| 13 | 9 | 1 (hang) | 0 |

**LibOQS nist-branch 2018-11**

| Test | Mall. | Crash/hang | Non-mall. |
|---|---|---|---|
| 2 | 3 | 0 | 0 |
| 3 | 4 | 6 (segf.) + 1 (ret. ⊥) | 0 |
| 4 | 9 | 7 (segf.) + 1 (hang) | 0 |
| 6 | 24 | 12 (segf.) + 7 (hang) | 0 |
| 7 | 3 | 9 (segf.) + 2 (stack overf.) + 4 (hang) | 0 |
| 10 | 6 | 0 | 0 |

Two things stand out. Test 6 has the largest counts in every version, which is mostly the FO "feature" (Section 10.1). And Test 13 in 0.14.0, the newest library, has 25 hits: strong unforgeability is the property most often missing from current code.

The paper also discusses hangs: sometimes a hang is preferable to silently using bad randomness. The better answer is health tests on the randomness source, which have their own problems.

## 9. Case studies

For each case: the symptom, which test caught it, the root cause, and what to check in your own code.

### 9.1 NTRU: unchecked padding bits break IND-CCA

**Symptom.** In LibOQS 0.4.0, NTRU-HRSS-701, NTRU-HPS-2048-677, and NTRU-HPS-2048-509 decapsulate a ciphertext with one flipped bit to the original shared secret. Caught by Test 7.

**Root cause.** The ciphertext packs `n − 1` coefficients of `log q` bits each, and that bit count is not a multiple of 8:

| Parameter set | Packed bits | Ciphertext bytes | Unused bits in the last byte |
|---|---|---|---|
| HPS-2048-509 | 508 × 11 = 5588 | 699 | 4 |
| HPS-2048-677 | 676 × 11 = 7436 | 930 | 4 |
| HRSS-701 | 700 × 13 = 9100 | 1138 | 4 |

The specification's `bits_to_bytes` zero-pads to the byte boundary, but decapsulation did not check that padding. Unpacking ignores the four high bits, so a ciphertext with any value there unpacks to the same polynomial. The [fix](https://github.com/jschanck/ntru/commit/6bb52396fed494001228ca579f4c1d91ef558171) [source] (January 2020, crediting Fernando Virdia and Greg Zaverucha) adds one line before decryption:

```c
/* Check that unused bits of last byte of ciphertext are zero */
fail |= c[NTRU_CIPHERTEXTBYTES-1] & (0xff << (8 - (7 & (NTRU_LOGQ*NTRU_PACK_DEG))));
```

For HPS-2048-509, `7 & 5588 = 4`, so the mask is `0xF0`: the four high bits must be zero.

*My reading:* the same commit shows why the usual FO re-encryption check did not catch the problem. The code next to the fix says that when decryption succeeds, `c = Enc(h, rm)` already holds, so there is "no need to re-encapsulate". That equality holds on the unpacked polynomial, not on the bytes. A byte-level re-encryption comparison would have caught the padding bits; an algebraic shortcut skipped it. If you take a shortcut around re-encryption, you take on the job of proving that the encoding is injective.

**Check in your code.** Every non-byte-aligned packing must reject non-zero padding on decode. Test 7 with a guard byte covers it automatically.

### 9.2 KNOT-384: output depends on the byte after the message

**Symptom.** In the optimized implementation of the KNOT-384 hash (NIST lightweight cryptography, round 1), messages whose length is a multiple of 6 bytes hash to different values depending on the first byte *after* the message in memory. Caught by Test 1's trailing guard byte, as a bit-exclusion failure.

**Root cause.** Wrong masking when converting between least-significant-bit-first and most-significant-bit-first integer representations.

**Disclosure.** The designers fixed it in a later round submission without disclosing it, and the SUPERCOP copy was not updated. SUPERCOP had in fact flagged KNOT-384's output as "nondeterministic" ([archived report](https://web.archive.org/web/20200810000404/https:/bench.cr.yp.to/web-impl/amd64-pmnod003-crypto_hash-knot384.html)), but nobody connected that to an over-read.

**Check in your code.** Run tests with guard bytes around every input buffer, at lengths around every block and word boundary. Sanitizers will not see this.

### 9.3 acehash and syconhash: second preimages in SIMD code

Three hash implementations in SUPERCOP fail second-preimage resistance: `acehash256v1` (SSE2) and `syconhash256v1` (AVX and SSE). The baseline sees segmentation faults from invalid reads in the same implementations, and the authors think the two are likely related. The paper stresses that these are bugs in specific implementations, not in the designs.

*My reading:* these are vectorized versions of correct reference designs. A per-kernel differential test against the reference implementation on random inputs would probably not catch an implementation that ignores one input bit in some lane (one slot of a SIMD register), because random inputs rarely differ in exactly that bit. A bit-contribution test catches it, because it flips every input bit.

### 9.4 Falcon: two encodings of zero

**Symptom.** Falcon in LibOQS 0.4.0 does not provide strong unforgeability, and neither did LibOQS 0.14.0 at the time of testing. Caught by Test 13.

**Root cause.** Falcon's compressed signature format encodes each coefficient as a sign bit, the low 7 bits, and the high bits in unary. The decoder accepted `100000001` ("−0") as a valid encoding of 0, and did not check that the signature was zero-padded. Both give a second byte string that decodes to the same signature. This was reported in [liboqs issue #1315](https://github.com/open-quantum-safe/liboqs/issues/1315) [source] in November 2022, citing Section 3.11.2 and Algorithms 17–18 of Falcon specification v1.2.

**Why it matters.** Falcon is a GPV hash-and-sign scheme, and GPV implies strong unforgeability (GPV08, Prop. 6.1). The Falcon design document did not say the property was missing, so users could reasonably expect it. The Falcon team had found the problem independently and fixed it in specification v1.2; LibOQS updated its copy shortly after disclosure.

### 9.5 SNOVA: unused trailing bits

For some SNOVA parameter sets in LibOQS 0.14.0, the last byte of the signature is not fully used, and the unused bits are accepted with any value. Same class as NTRU: a non-byte-aligned encoding without a padding check.

### 9.6 CROSS: the ignored length

**Symptom.** PQClean is a collection of portable, cleaned-up implementations of PQC schemes with a common API. In the PQClean-compatible CROSS implementation, any valid signature with extra bytes appended still verifies. Caught by Test 13's length tampering.

**Root cause.** The PQClean API passes the signature length into `crypto_sign_verify`. CROSS has fixed-length signatures, and its implementation ignored the parameter. Other PQClean implementations (ML-DSA, SPHINCS+) reject a wrong length. Reported as [CROSS-lib-oqs issue #1](https://github.com/CROSS-signature/CROSS-lib-oqs/issues/1) [source] in September 2025.

The implementations submitted to NIST did not have the bug, because a similar test already existed there. *My reading:* this is a reminder that every packaging of an algorithm (NIST API, PQClean API, liboqs wrapper) is its own implementation and needs its own negative tests.

### 9.7 Crashing decapsulation is an oracle

In `nist-branch` 2018-11, Big Quake, LEDAkem, and LIMA crash or hang when decapsulating a tampered ciphertext. A crash is an observable difference, so it works as a **ciphertext-validity oracle**: an attacker learns whether a ciphertext was well-formed. This kind of leak is the basis of plaintext-checking attacks on FO-based KEMs. In such an attack, the attacker sends crafted ciphertexts and uses each yes/no answer to learn a little about the secret key.

### 9.8 Not bugs: schemes that never claimed IND-CCA

Test 7 also fires on the ephemeral ThreeBears and SIKE variants in LibOQS 0.4.0, and on a BIKE variant in `nist-branch`. These variants do not claim IND-CCA, so the tests are reporting the design correctly. A test suite should let you mark such variants as expected.

## 10. "Features": not bugs, but surprising

This part explains the "Features" in the title, and I found it the most interesting. These properties come from the scheme definitions, not from implementation mistakes. They do not break IND-CCA or EUF-CMA, but a protocol or key-management system that assumes otherwise can break.

### 10.1 KEM secret keys are malleable under FO implicit rejection

Many KEMs build IND-CCA security from a passively secure scheme with the Fujisaki–Okamoto transform. In the implicit-rejection variants (Hofheinz–Hövelmanns–Kiltz), the secret key carries a random string `z` that is only used to derive a pseudorandom key when the ciphertext is invalid. Take ML-KEM decapsulation (FIPS 203, Algorithm 18) as an illustration:

```text
m'      ← K-PKE.Decrypt(dk_PKE, c)
(K', r') ← G(m' || h)
K̄       ← J(z || c)          # rejection key
c'      ← K-PKE.Encrypt(ek, m', r')
if c ≠ c': K' ← K̄
return K'
```

![FO implicit rejection: for a valid ciphertext the output key comes from G(m' || h), and the rejection key J(z || c) is computed but discarded, so changing z does not change the output](./diagrams/fo-implicit-rejection.svg)

For a valid ciphertext, `J(z || c)` is computed and then discarded. It is always computed so that the running time does not depend on whether the ciphertext is valid. Flip any bit of `z` and decapsulation returns the same key. The paper attributes every Test 6 hit on IND-CCA KEMs in LibOQS 0.8.0 and 0.4.0 to this.

**When it matters.** A system that checks "this secret key decapsulates correctly" to validate a stored key will accept a key whose `z` was corrupted, and the corruption only shows when an invalid ciphertext arrives. *My reading:* FIPS 203 added a secret-key hash check to decapsulation input validation, which covers the `h = H(ek)` part of the key; integrity of `z` still has to come from elsewhere.

### 10.2 Randomized Dilithium ignores part of its secret key

Dilithium's secret key contains a 256-bit value `K`. The deterministic variant derives signing randomness from `K` and the message. The randomized variant samples fresh randomness and ignores `K`. Both variants share one key format. With the RNG seed fixed in the test, two secret keys that differ only in `K` produce identical signatures (Test 8). In deployment, you would only notice this if the signing randomness source were faulty.

*My reading:* ML-DSA (FIPS 204) changes this. Its hedged signing, which mixes fresh randomness `rnd` with secret-key material, derives the signing seed as `ρ'' ← H(K || rnd || μ)`, so `K` contributes in both modes. Rerunning Test 8 on ML-DSA would be a cheap way to confirm the property is gone.

### 10.3 Public keys that can be modified: exclusive ownership

In LibOQS 0.4.0, Rainbow and Falcon public keys could be changed into a different `pk' ≠ pk` such that a valid `(pk, m, σ)` still verifies as `(pk', m, σ)` (Test 11, since resolved). This resembles a break of **conservative exclusive ownership** (CEO, Pornin–Stern 2005): given a valid signature, find another public key under which it verifies. Here the attacker does not learn a secret key for `pk'`, which rules out impersonation attacks. But it does satisfy the conditions for the **strong** variants, S-CEO (Cremers et al., "BUFFing signature schemes", S&P 2021) and S-UEO (Brendel et al., S&P 2021), which drop the requirement that the adversary knows a matching secret key.

How much this matters in deployed protocols is unclear, and the paper does not overclaim. Jackson et al. (CCS 2019) showed that such subtle signature properties do break real protocols for classical schemes, so the question is worth asking for PQC.

## 11. Head-to-head with the baseline

| Library | Found by both | Found only by the cryptographically-informed tests | Found only by the baseline |
|---|---|---|---|
| LibOQS 0.4.0 | SIKE/SIDH compressed variants segfault in `Encaps` | 10 IND-CCA counterexamples; 9 sUF-CMA counterexamples; 3 Picnic buffer overflows | none: the baseline's 9 Picnic `Sign` segfaults include 6 variants that the new tests flagged through the random-tape test instead |
| LibOQS nist-branch 2018-11 | all 12 `Decaps` segfaults, the `Decaps` hang, all 5 `Encaps` segfaults | 3 IND-CCA counterexamples | **Dilithium III aborts; Picnic_L3_UR segfaults** |
| LibOQS 0.8.0 | — | 2 sUF-CMA counterexamples | — |
| LibOQS 0.14.0 | — | 25 sUF-CMA counterexamples | — |
| SUPERCOP 20240107 | segfaults in acehash256v1 (AVX, SSE2) and syconhash256v1 (AVX, SSE), all invalid reads | second-preimage failures, likely the same root cause | — |

Totals: **13 IND-CCA and 36 sUF-CMA counterexamples** that the baseline did not catch, plus the S-CEO/S-UEO-type properties. The authors expect that a stronger baseline fuzzer would not change this, because violations of a security notion do not crash; only a harness that encodes the notion can see them. They frame cryptographically-informed testing as a complement to traditional fuzzing and compiler flags, not a replacement.

## 12. Assessment

### 12.1 What the paper does well

- **A simple method with real results.** It needs no symbolic execution and no formal model. A sentence such as "a tampered ciphertext must not decapsulate to the original key" becomes an executable check, and it found real, fixed bugs.
- **The format string is a good abstraction.** One list of `(length, label)` expresses "these bits must matter" and "these bits must not", and the guard bytes add over-read detection without extra code. It is reusable across primitives and libraries.
- **It identifies a bug class.** NTRU, Falcon, SNOVA, and CROSS follow one pattern: the decoder accepts more than one byte string for the same object. Specifications often state the canonical form in half a sentence ("padding bits are zero"), which is easy to miss in code and simple to test.
- **It separates bugs from features honestly.** The 200+ malleabilities are not presented as 200 vulnerabilities. The paper distinguishes implementation bugs, intended properties, and surprising properties.
- **It is easy to adopt.** LibOQS and SUPERCOP share the SUPERCOP-style API, so the test code needs little adaptation. The authors suggest adding the tests as an optional mode to SUPERCOP and to Project Wycheproof (Google's collection of test vectors for known attacks). I agree.

### 12.2 Limitations and open questions

- **The mutation set is narrow.** Single bit flips, all zeros, all ones, and 256 bad-RNG bytes. Bugs that need two coordinated changes (e.g. keeping an internal checksum valid) or a structured value (a coefficient equal to `q`, a hint index out of order) are not covered. The only metamorphic relation used is equal/different.
- **Coverage guidance is unused.** The mutation schedule is deterministic, so AFL++ is a runner. That is a design choice, not a flaw, but "fuzzing" here means exhaustive metamorphic testing more than coverage-guided exploration.
- **One starting point per test.** Every test starts from one valid input from a fixed seed. Bugs that need a particular key or message (a rare rejection-sampling branch, an edge-case coefficient) can be missed. The baseline found two crashes the new tests did not, which is consistent with this.
- **Counts are of affected combinations.** Counting per (scheme, parameter set, version) and including intended properties inflates the totals. Cite the case studies, not "200+".
- **Hashes get one test.** Near-collisions and output uniformity are left as future work, and the Update test has no PQC counterpart.
- **Mostly historical targets.** Deliberate, and defensible, but the results describe implementation quality during standardization more than today's production libraries. The 0.14.0 findings on Falcon, SNOVA, and CROSS show that recent code has the same problems.

### 12.3 What I would add

*My reading*, as someone who writes optimized kernels:

1. **Structured mauls next to bit flips.** For lattice schemes, encode a coefficient as `q`, `q + 1`, or `2^k − 1` in its packed field, swap two hint indices, set a length to its maximum. These target exactly the "decode must be injective" checks that FIPS 203/204 added (modulus check, hint ordering).
2. **Run the same format string on every backend.** Reference, AVX2, AVX-512, and Cortex-M4 code should return identical bytes *and* identical return codes on every tampered input. A mismatch is either a bug or a timing/behavior difference between dispatch paths.
3. **Combine with constant-time checks.** The paper suggests dudect, a tool that measures running times on two classes of inputs and applies a statistical test. A cheaper first step is to run the Test 7 loop under Valgrind with the secret key marked as undefined memory; Valgrind then reports every branch or memory address that depends on it. Every tampered ciphertext runs the rejection path, which is where FO timing leaks usually occur.
4. **Put a small budget in CI.** Test 7 and Test 13 alone, on the default parameter sets, run in minutes and cover the two notions that matter most.

## 13. How this maps to the NGCC first-round findings

In my earlier post on [engineering PQC implementations](../pqc-implementation-guide/), I grouped the 65 implementation findings from the NGCC first-round review into nine categories. Here is which categories these tests would catch, and which they would not.

| NGCC category (earlier post, 5.1) | Covered? | Test(s) | Notes |
|---|---|---|---|
| 1. Security budget truncated by the code | No | — | A length error does not change whether a bit matters. Needs static assertions on parameters |
| 2. Wrong FO transform implementation | **Yes** | 7, 6 | "Compares only every 4th byte" (kem-02-1) is exactly a Test 7 malleability |
| 3. Randomness problems | Partly | 2, 5, 10 | Bad-RNG tests find hangs; "two calls must differ" is the −3 step inverted, easy to add |
| 4. Input parsing and memory safety | **Yes** | 3, 4, 6, 7, 11–13 | Segfaults and overflows under tampering; guard bytes add over-reads |
| 5. Non-injective encoding / malleability | **Yes** | 7, 11, 13 | The NTRU/Falcon/SNOVA/CROSS class |
| 6. Code does not match the spec | No | — | Needs an independent executable model and intermediate-value comparison |
| 7. State management | No | — | Stateful APIs are outside the syntax |
| 8. Protocol-level omissions | No | — | Outside the primitive |
| 9. Leftover debug code | Rarely | — | Only if it changes outputs |

Roughly: the tests cover the categories where the property can be stated as "this input must or must not affect that output". They do not replace an independent model of the specification.

The earlier post also cited the KpqC first-round analysis ([ePrint 2023/1437](https://eprint.iacr.org/2023/1437)), which already applied metamorphic testing to Korean candidates. This paper gives that practice a reusable form.

## 14. A minimal harness you can adapt

The [authors' code](https://github.com/jangilcher/cryptoTesting) runs in Docker: `bash run.sh` opens a container, and `bash reproduce.sh ches_liboqs` reproduces the LibOQS 0.14.0 run (`cur_liboqs` for 0.8.0, `mid_liboqs` for 0.4.0, `old_liboqs` for 2018-11, `supercop` for hashes; append `baseline` for the plain AFL++ runs) [source]. The README notes that hang counts depend on CPU speed and out-of-bounds writes do not always segfault, so reproduced numbers can differ slightly.

If you only want Tests 7 and 13 for your own library, you do not need AFL++. The sketch below uses the public liboqs API and a deterministic RNG. **It is a sketch: I have not compiled it against a specific liboqs release, so check the API of your version.** Error handling and frees are omitted.

```c
#include <oqs/oqs.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Deterministic RNG: every run sees the same keys and coins. */
static uint64_t s = 0x243f6a8885a308d3ULL;
static void fixed_rng(uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        s ^= s << 13; s ^= s >> 7; s ^= s << 17;
        out[i] = (uint8_t)s;
    }
}

static void flip(uint8_t *b, size_t bit) { b[bit / 8] ^= (uint8_t)(1u << (bit % 8)); }

/* Test 7: Decaps(sk, Maul(c)). Layout: guard || c || guard. */
static int test_decaps_ct(const char *name) {
    OQS_KEM *kem = OQS_KEM_new(name);
    if (kem == NULL) return -1;
    size_t clen = kem->length_ciphertext, sslen = kem->length_shared_secret;
    uint8_t *pk = malloc(kem->length_public_key), *sk = malloc(kem->length_secret_key);
    uint8_t *buf = malloc(clen + 2), *ss = malloc(sslen);
    uint8_t *ss0 = malloc(sslen), *ss1 = malloc(sslen);

    OQS_KEM_keypair(kem, pk, sk);
    buf[0] = buf[clen + 1] = 0xFF;
    OQS_KEM_encaps(kem, buf + 1, ss, pk);
    OQS_STATUS rv0 = OQS_KEM_decaps(kem, ss0, buf + 1, sk);

    int bad = 0;
    for (size_t bit = 0; bit < 8 * (clen + 2); bit++) {
        int in_ct = bit >= 8 && bit < 8 * (clen + 1);  /* DIFF region */
        flip(buf, bit);
        OQS_STATUS rv1 = OQS_KEM_decaps(kem, ss1, buf + 1, sk);
        int same = rv0 == rv1 && memcmp(ss0, ss1, sslen) == 0;
        if (same == in_ct) {  /* DIFF but same, or EQ but different */
            printf("%s: bit %zu: %s\n", name, bit, in_ct ? "malleable ciphertext" : "reads outside c");
            bad++;
        }
        flip(buf, bit);
    }
    OQS_KEM_free(kem);
    return bad;
}

/* Test 13: Verify(pk, m, Maul(sigma)), including the length. */
static int test_verify_sig(const char *name) {
    OQS_SIG *sig = OQS_SIG_new(name);
    if (sig == NULL) return -1;
    size_t cap = sig->length_signature + 16, siglen;
    uint8_t *pk = malloc(sig->length_public_key), *sk = malloc(sig->length_secret_key);
    uint8_t *buf = calloc(cap + 2, 1), msg[32];
    memset(msg, 42, sizeof msg);

    OQS_SIG_keypair(sig, pk, sk);
    buf[0] = buf[cap + 1] = 0xFF;
    OQS_SIG_sign(sig, buf + 1, &siglen, msg, sizeof msg, sk);

    int bad = 0;
    for (size_t len = 0; len <= cap; len++)  /* any other length must fail */
        if (len != siglen &&
            OQS_SIG_verify(sig, msg, sizeof msg, buf + 1, len, pk) == OQS_SUCCESS) {
            printf("%s: accepts length %zu (true length %zu)\n", name, len, siglen);
            bad++;
        }
    for (size_t bit = 8; bit < 8 * (siglen + 1); bit++) {  /* every signature bit */
        flip(buf, bit);
        if (OQS_SIG_verify(sig, msg, sizeof msg, buf + 1, siglen, pk) == OQS_SUCCESS) {
            printf("%s: bit %zu: malleable signature\n", name, bit - 8);
            bad++;
        }
        flip(buf, bit);
    }
    OQS_SIG_free(sig);
    return bad;
}

int main(int argc, char **argv) {
    OQS_init();
    OQS_randombytes_custom_algorithm(fixed_rng);
    if (argc == 3 && strcmp(argv[1], "kem") == 0) return test_decaps_ct(argv[2]) != 0;
    if (argc == 3 && strcmp(argv[1], "sig") == 0) return test_verify_sig(argv[2]) != 0;
    fprintf(stderr, "usage: %s kem|sig ALGORITHM\n", argv[0]);
    return 2;
}
```

Notes on the sketch:

- Test 7's loop also flips the two guard bytes (the `EQ` regions), so it checks over-reads as well.
- For a scheme that does not claim strong unforgeability, a Test 13 hit is information, not necessarily a bug.
- Add Valgrind secret marking around `OQS_KEM_decaps` to turn the same loop into a rejection-path constant-time test (Section 12.3).
- To test a non-liboqs implementation, replace the four API calls. The loop structure is the whole method.

## 15. Checklist for your own implementation

Each item corresponds to a finding in the paper.

**Encoding**

- [ ] Every non-byte-aligned packing rejects non-zero padding bits on decode (NTRU, SNOVA)
- [ ] Every value has exactly one accepted encoding; reject "−0" and other aliases (Falcon)
- [ ] Decode → re-encode is byte-for-byte equal, or the input is rejected

**Lengths and buffers**

- [ ] Every length parameter is used and checked; a wrong signature or ciphertext length is rejected (CROSS)
- [ ] Outputs do not depend on bytes outside the input buffer; tested with guard bytes at lengths around every block boundary (KNOT-384)

**KEM**

- [ ] Flipping any ciphertext bit gives a different key, or an error that does not depend on secrets (Test 7)
- [ ] Decapsulation of tampered ciphertexts never crashes or hangs (Big Quake, LEDAkem, LIMA)
- [ ] If decapsulation skips re-encryption, the encoding is proven injective at the byte level (NTRU)
- [ ] Documentation states which parts of the secret key are unused for valid ciphertexts (FO `z`)

**Signatures**

- [ ] Flipping any signature bit, or changing the length, makes verification fail, if the scheme claims or implies sUF-CMA (Test 13)
- [ ] Tampered public keys do not verify existing signatures (Test 11)
- [ ] Documentation states whether randomized signing uses all of the secret key (Dilithium `K`)

**Randomness and robustness**

- [ ] A constant random tape leads to an error or a bounded retry, never an infinite loop (Tests 2, 5, 10)
- [ ] Return values are part of every test; failure paths return an error and clear outputs

**Process**

- [ ] Tests 7 and 13 run in CI on every backend (ref, AVX2, AVX-512, embedded), with identical outputs and return codes
- [ ] Every API packaging (NIST, PQClean, liboqs) has its own negative tests

## Sources

- Fenzi, Gilcher, Virdia, "Finding Bugs and Features Using Cryptographically-Informed Functional Testing", [TCHES 2026(1), pp. 425–447](https://doi.org/10.46586/tches.v2026.i1.425-447); [ePrint 2024/1122](https://eprint.iacr.org/2024/1122); [code and reproduction instructions](https://github.com/jangilcher/cryptoTesting) [source]
- Mouha, Raunak, Kuhn, Kacker, "Finding Bugs in Cryptographic Hash Function Implementations", IEEE Transactions on Reliability 67(3), 2018
- [NTRU fix: "Ensure trailing bits of ciphertext are 0"](https://github.com/jschanck/ntru/commit/6bb52396fed494001228ca579f4c1d91ef558171) [source]
- [liboqs issue #1315: Malleable Falcon signatures](https://github.com/open-quantum-safe/liboqs/issues/1315) [source]
- [CROSS-lib-oqs issue #1: Potential SUF-CMA violation](https://github.com/CROSS-signature/CROSS-lib-oqs/issues/1) [source]
- [SUPERCOP report on KNOT-384 (archived)](https://web.archive.org/web/20200810000404/https:/bench.cr.yp.to/web-impl/amd64-pmnod003-crypto_hash-knot384.html)
- Cremers, Düzlü, Fiedler, Fischlin, Janson, "BUFFing Signature Schemes Beyond Unforgeability and the Case of Post-Quantum Signatures", IEEE S&P 2021
- Brendel, Cremers, Jackson, Zhao, "The Provable Security of Ed25519: Theory and Practice", IEEE S&P 2021
- Jackson, Cremers, Cohn-Gordon, Sasse, "Seems Legit: Automated Analysis of Subtle Attacks on Protocols that Use Signatures", ACM CCS 2019
- Kannwischer, Schwabe, Stebila, Wiggers, "Improving Software Quality in Cryptography Standardization Projects", [ePrint 2022/337](https://eprint.iacr.org/2022/337)
- [Security analysis of KpqC first-round implementations, ePrint 2023/1437](https://eprint.iacr.org/2023/1437)
- [FIPS 203 (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final) and [FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final)
