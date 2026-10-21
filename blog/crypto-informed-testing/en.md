# Flip One Bit: What Cryptographically-Informed Testing Finds in PQC Implementations

*For anyone who writes or tests cryptographic code · ~25 min read · October 21, 2026*

Here is a real bug. In 2020, the NTRU key encapsulation code in LibOQS (a widely used C library of post-quantum schemes) had a ciphertext whose last byte contained four unused bits. The code ignored those bits. So if you changed one of them, the changed ciphertext still decrypted to the original secret key. The code passed all its known-answer tests, and it never crashed. Yet this one detail meant the scheme no longer had the security property it claimed.

This post explains a simple way to find bugs like this automatically. The method comes from a TCHES 2026 paper by Giacomo Fenzi, Jan Gilcher, and Fernando Virdia ([paper](https://doi.org/10.46586/tches.v2026.i1.425-447), [ePrint 2024/1122](https://eprint.iacr.org/2024/1122), [code](https://github.com/jangilcher/cryptoTesting)). I explain the idea first, then the bugs it found, then how to use it on your own code.

> **In one sentence:** take a valid input, flip one bit, and check that the output changes when it should change and stays the same when it should not.

## 0. What this post covers

You do not need to know the paper. You need to know what a key encapsulation mechanism (KEM) and a digital signature do. Everything else is explained when it first appears.

The main points:

1. **The most important security bugs do not crash.** A normal fuzzer looks for crashes. It found nothing in recent LibOQS versions. The paper's tests found dozens of cases where a security property was broken.
2. **Most real bugs are about encoding.** The same value could be written as more than one byte string, and the code accepted all of them. NTRU, Falcon, SNOVA, and CROSS all had this kind of bug.
3. **The method is cheap.** It is a short loop around the function you want to test. A full run over one library version takes about half a day on a server.
4. **Not every finding is a bug.** Some surprising results come from how the schemes are designed. The paper separates these from real bugs, and so does this post.
5. **The idea can go further than the paper.** Section 9 adds eight more checks of the same kind. Each one is based on a bug that was published in the public review of China's NGCC competition and that the paper's tests would miss.

This post follows on from my earlier post, [Engineering PQC Implementations](../pqc-implementation-guide/). That post lists eleven kinds of tests a PQC implementation needs (its Section 7.1). This post looks at one of them, metamorphic testing, in detail.

Note: links marked [source] were checked while writing. Paragraphs that start with *My note* are my own interpretation, not claims from the paper.

## 1. Why normal tests miss this kind of bug

Developers usually test cryptographic code in three ways:

| Test | What it does | Why it missed the NTRU bug |
|---|---|---|
| Known-answer tests (KATs) | Run the code on a fixed list of inputs and compare the outputs with stored correct outputs | All test inputs were valid ciphertexts. None had a changed padding bit |
| Sanitizers (for example AddressSanitizer) | Stop the program when it reads or writes memory it does not own | The code read only its own memory. It just ignored some bits |
| Fuzzing (for example [AFL++](https://www.usenix.org/conference/woot20/presentation/fioraldi)) | Run the code on many random inputs and record crashes | Nothing crashed. The wrong result looked like a normal result |

The root problem is this. Cryptographic outputs are designed to look random. If a test sees a key like `3f a1 9c ...`, it cannot tell whether that key is correct. Software testing calls this the **oracle problem** ([Weyuker, 1982](https://doi.org/10.1093/comjnl/25.4.465)). An "oracle" is anything that can say whether an output is right.

So the question is: how do you test code when you cannot tell whether a single output is correct?

## 2. The idea: compare two outputs instead of checking one

You often cannot say whether one output is correct. But you can often say how *two* outputs must relate to each other. This is called **metamorphic testing** ([Chen, Cheung, Yiu, 1998](https://arxiv.org/abs/2002.12543); [Chen, Tse, Zhou, 2003](https://doi.org/10.1016/S0950-5849%2802%2900129-5)).

A hash function is the simplest example. You do not know what `H(x)` should be. But you know two rules:

- **Rule 1: every input bit must matter.** If you flip any bit of the message, the hash must change. If it does not change, the code ignores that bit.
- **Rule 2: bytes outside the input must not matter.** If you change a byte just after the end of the message in memory, the hash must stay the same. If it changes, the code reads past the end of its input.

Each rule gives a test you can run without knowing the correct answer. Flip one bit, compute the output again, and compare.

This is not a new idea for hash functions. In 2018, [Mouha, Raunak, Kuhn, and Kacker](https://doi.org/10.1109/TR.2018.2847247) used these rules on 86 reference implementations from the SHA-3 competition. 19 broke rule 1, and 17 broke rule 2. Two of the five SHA-3 finalists had such bugs.

The new paper applies the same idea to KEMs and digital signatures.

### 2.1 Guard bytes

To check rule 2, the test puts one extra byte before the input and one after it. These are called **guard bytes**. The function under test receives a pointer to the real input, so it should never look at the guard bytes. If flipping a guard byte changes the output, the function read outside its input.

![Test 7 buffer layout: a guard byte, the ciphertext marked DIFF including the last byte's padding bits, and a trailing guard byte; flipping the guard must leave the output unchanged, flipping any ciphertext bit must change it](./diagrams/buffer-layout.svg)

The figure shows the layout for a KEM ciphertext. Every bit of the ciphertext, including the padding bits, is marked "must change the output" (DIFF). The guard bytes are marked "must not change the output" (EQ). The NTRU bug is the orange part: flipping a padding bit did not change the key.

*My note:* guard bytes find a bug that sanitizers miss. A sanitizer only complains when code touches memory that is not allocated. Reading the next byte of a larger, valid buffer looks fine to it.

## 3. From security definitions to simple checks

Security definitions sound abstract. But each one gives a very concrete check.

**IND-CCA (for KEMs).** This is the standard security goal for a KEM. In plain words: an attacker may ask the system to decapsulate any ciphertext except the one they are attacking, and still must learn nothing about the key inside that one.

Now suppose flipping one bit of a ciphertext gives the same key. The attacker takes the target ciphertext, flips one bit, and asks the system to decapsulate the new ciphertext. This is allowed, because it is a different ciphertext. The system returns the key. The attacker now knows the target key. The security is completely broken.

So the check is: **flip any bit of a valid ciphertext, decapsulate, and the key must be different.**

**Strong unforgeability (sUF-CMA, for signatures).** The usual goal for signatures is that nobody can sign a *new* message. Strong unforgeability asks for more: nobody can produce even a *second, different signature* for a message that was already signed. Some protocols rely on this, for example when they use a signature as a unique ID for a transaction.

So the check is: **flip any bit of a valid signature (or change its length), and verification must fail.**

Not every scheme claims strong unforgeability. NIST did not require it. When a scheme does not claim it, a failed check is useful information but not a bug.

**Second-preimage resistance (for hashes).** It must be hard to find a second message with the same hash. The check is rule 1 from Section 2: flipping a bit must change the hash.

| Security goal | Check | If the check fails |
|---|---|---|
| IND-CCA (KEM) | Flip a ciphertext bit, decapsulate; the key must change | The scheme is broken: an attacker learns the key |
| sUF-CMA (signature) | Flip a signature bit or change its length; verification must fail | Signatures are malleable. A bug if the scheme claims sUF-CMA |
| Second preimage (hash) | Flip a message bit; the hash must change | The implementation ignores part of its input |

## 4. How the test program works

The test program follows the same steps every time:

1. **Make a valid input.** For example, generate a key pair and a valid ciphertext.
2. **Compute the normal output.** For example, decapsulate the ciphertext and store the key.
3. **Change one bit** of the input.
4. **Compute the output again.**
5. **Compare.** Depending on where the bit was, the output must either change or stay the same. If the result is wrong, the program crashes on purpose.

Steps 3 to 5 repeat for every bit of the input. The program crashes on purpose so that a fuzzer like AFL++ records the input that caused the problem. AFL++ is used here only to run many tests in parallel and to save the failing inputs.

![The Test loop: GenInput produces a baseline, Maul flips one bit and states the expectation, Call reruns the function, Match aborts on a mismatch, and AFL++ stores the crashing input](./diagrams/test-loop.svg)

The paper names the four parts `GenInput` (steps 1 and 2), `Maul` (step 3; "maul" means to damage), `Call` (step 4), and `Match` (step 5). Only `Call` depends on the scheme being tested. The other parts are written once and reused for every scheme and every library.

Before flipping single bits, the test also tries three simple cases: the input unchanged (the output must be the same), the input set to all zeros, and the input set to all ones.

### 4.1 Two extra details

**Random numbers.** Key generation, encapsulation, and signing use random bytes. To make tests repeatable, the test fixes the random bytes. The paper also tests a broken random number generator that returns the same byte over and over. Some implementations then run forever, for example key generation that keeps rejecting candidates and never finishes. That is not a security break, but it is a bug.

**Lengths.** Some signatures have variable length, so the length is passed as a separate number. The test changes this number too. This is how the CROSS bug in Section 6.5 was found.

### 4.2 The thirteen tests

The paper applies the loop to every input of every function:

| Test | Function | What is changed | What must happen |
|---|---|---|---|
| 1 | Hash | the message | hash changes; guard bytes have no effect |
| 2 | KEM / signature key generation | the random bytes | keys change; no infinite loop |
| 3 | KEM encapsulation | the public key | output changes |
| 4 | KEM encapsulation, then decapsulation with the original secret key | the public key | the two keys differ |
| 5 | KEM encapsulation | the random bytes | output changes |
| 6 | KEM decapsulation | the secret key | key changes |
| 7 | KEM decapsulation | the ciphertext | key changes (**IND-CCA**) |
| 8 | Signing | the secret key | signature changes |
| 9 | Signing | the message | signature changes |
| 10 | Signing | the random bytes | signature changes (unless the scheme is deterministic) |
| 11 | Verification | the public key | verification fails |
| 12 | Verification | the message | verification fails |
| 13 | Verification | the signature and its length | verification fails (**sUF-CMA**) |

Tests 7 and 13 are the most important. They check the two main security goals directly.

## 5. What the tests found

The authors tested four versions of LibOQS (from 2018, 2020, 2023, and 2025) and the hash functions in SUPERCOP (a benchmarking suite that collects many implementations). They tested old versions on purpose, because LibOQS removes schemes that drop out of the NIST competition, and old versions still contain them.

For comparison, they also ran a normal fuzzer on the same code. It only looks for crashes.

| Library version | Normal fuzzer found | Paper's tests found (in addition) |
|---|---|---|
| LibOQS 2018 (`nist-branch`) | 27 crashes, 1 hang | 3 IND-CCA breaks |
| LibOQS 0.4.0 (2020) | 17 crashes, 1 hang | 10 IND-CCA breaks, 9 sUF-CMA breaks, 3 buffer overflows |
| LibOQS 0.8.0 (2023) | nothing | 2 sUF-CMA breaks |
| LibOQS 0.14.0 (2025) | nothing | 25 sUF-CMA breaks |

In total, the paper's tests found 13 IND-CCA breaks and 36 sUF-CMA breaks that the normal fuzzer could not see. They also caught almost all of the crashes that the normal fuzzer found. The exceptions were two crashes in Dilithium III and Picnic_L3_UR, which the normal fuzzer found and the paper's tests missed.

Two notes on the numbers:

- The paper counts every (scheme, parameter set, library version) separately. One bug that affects two parameter sets in two versions counts four times. So these are not counts of distinct bugs.
- Not every result is a bug. Some schemes never claimed sUF-CMA, and some results come from scheme design (Section 7).

A full run takes about half a day per library version on a server with 31 to 75 cores. The full tables are in Appendix A.

## 6. Real bugs, one by one

Each case below follows the same pattern: what happened, why, and how to avoid it.

### 6.1 NTRU: unused bits in the ciphertext

**What happened.** In LibOQS 0.4.0, three NTRU parameter sets (HRSS-701, HPS-2048-677, HPS-2048-509) accepted a ciphertext with a flipped bit and returned the original key. Test 7 found it. This broke IND-CCA.

**Why.** The ciphertext stores numbers of 11 or 13 bits each. The total number of bits is not a multiple of 8, so the last byte has 4 unused bits:

| Parameter set | Bits of data | Bytes | Unused bits in the last byte |
|---|---|---|---|
| HPS-2048-509 | 508 × 11 = 5588 | 699 | 4 |
| HPS-2048-677 | 676 × 11 = 7436 | 930 | 4 |
| HRSS-701 | 700 × 13 = 9100 | 1138 | 4 |

The specification says these bits are zero. But decapsulation never checked them. The [fix](https://github.com/jschanck/ntru/commit/6bb52396fed494001228ca579f4c1d91ef558171) [source] adds one check that rejects the ciphertext if any of these bits is set:

```c
/* Check that unused bits of last byte of ciphertext are zero */
fail |= c[NTRU_CIPHERTEXTBYTES-1] & (0xff << (8 - (7 & (NTRU_LOGQ*NTRU_PACK_DEG))));
```

*My note:* many KEMs re-encrypt during decapsulation and compare the result with the received ciphertext byte by byte. That comparison would have caught this bug. NTRU does not re-encrypt. Its decryption checks the decoded numbers directly, and the unused bits are dropped during decoding, so no check ever saw them.

**How to avoid it.** Whenever data does not fill the last byte, check that the unused bits are zero when you decode.

### 6.2 KNOT-384: reading past the end of the message

**What happened.** KNOT-384 is a hash function from the NIST lightweight cryptography competition. In its optimized code, for messages whose length is a multiple of 6 bytes, the hash depended on the byte right *after* the message in memory. The guard byte in Test 1 found it.

**Why.** A bit mask was wrong in a function that converts between two bit orders.

**How to avoid it.** Test with guard bytes, at many input lengths. Sanitizers do not find this.

### 6.3 acehash and syconhash: ignored input bits

Three vectorized (SIMD) hash implementations in SUPERCOP, `acehash256v1` (SSE2) and `syconhash256v1` (AVX and SSE), sometimes gave the same hash for two messages that differ in one bit. The designs are fine; these specific implementations are wrong.

*My note:* comparing a fast implementation with the reference code on random inputs would likely miss this. Random inputs rarely differ in exactly the one bit that is ignored. Flipping every bit, one by one, finds it every time.

### 6.4 Falcon: two ways to write zero

**What happened.** Falcon signatures in LibOQS 0.4.0 were malleable: a changed signature still verified. Test 13 found it. The same issue was still present in LibOQS 0.14.0 when the authors tested it.

**Why.** Falcon stores each number in a signature as a sign bit plus the size of the number. The decoder accepted a "negative zero" (sign bit set, size zero) as a valid zero. It also did not check that the padding at the end was zero. So one signature could be written in several ways ([liboqs issue #1315](https://github.com/open-quantum-safe/liboqs/issues/1315) [source]).

**Why it matters.** Falcon is built on the [GPV framework](https://eprint.iacr.org/2007/432), which normally gives strong unforgeability. Users could expect Falcon to have it. The Falcon team fixed this in version 1.2 of the specification.

**How to avoid it.** Accept exactly one encoding for each value. Reject "−0" and non-zero padding.

### 6.5 SNOVA and CROSS: unused bits and an ignored length

- **SNOVA** (a newer signature candidate): for some parameter sets, the last byte of the signature has unused bits, and any value was accepted there. This is the same problem as NTRU.
- **CROSS** (another signature candidate): its verification function received the signature length but ignored it. So you could add any bytes to the end of a valid signature and it still verified ([issue](https://github.com/CROSS-signature/CROSS-lib-oqs/issues/1) [source]). This was only in the version written for the PQClean API (PQClean is a collection of portable PQC code); the version submitted to NIST was fine.

**How to avoid it.** Check every length argument. Reject a signature whose length is not exactly right.

### 6.6 Crashes as a leak

In the 2018 LibOQS version, three KEMs (Big Quake, LEDAkem, LIMA) crashed or hung when given a changed ciphertext. A crash is visible to an attacker. It tells the attacker "this ciphertext was not valid". Attacks on KEMs can use exactly this kind of yes/no answer to recover the secret key, one query at a time.

### 6.7 Not a bug: schemes that never claimed IND-CCA

Test 7 also failed for some variants that are designed without IND-CCA, for example ephemeral (one-time-key) versions of ThreeBears and SIKE. These are correct by design. A test suite should let you mark them as expected.

## 7. Surprising, but not bugs

Some results are not mistakes in the code. They come from how the schemes are designed. They do not break the official security goals. But they may surprise someone who builds a system on top of the scheme.

### 7.1 Part of a KEM secret key is never used for valid ciphertexts

Most post-quantum KEMs, including ML-KEM, use the [Fujisaki–Okamoto (FO) transform](https://doi.org/10.1007/3-540-48405-1_34) to reach IND-CCA security. In its common "implicit rejection" form ([Hofheinz, Hövelmanns, Kiltz](https://eprint.iacr.org/2017/604)), the secret key contains a random value `z`. It is used only when the ciphertext is invalid: then the KEM returns a fake key derived from `z`, instead of an error.

![FO implicit rejection: for a valid ciphertext the output key comes from G(m' || h), and the rejection key J(z || c) is computed but discarded, so changing z does not change the output](./diagrams/fo-implicit-rejection.svg)

For a valid ciphertext, the fake key is computed (so that the timing is the same in both cases) and then thrown away. So if you change `z`, decapsulation of a valid ciphertext still gives the right key. This is why Test 6 reports many results even for correct KEMs.

**When it matters.** Suppose a system checks a stored secret key by decapsulating one valid ciphertext. A key with a damaged `z` passes this check. The damage only shows later, when an invalid ciphertext arrives.

### 7.2 Randomized Dilithium ignores part of its secret key

The Dilithium secret key contains a 256-bit value `K`. The deterministic version of Dilithium uses `K` to make signing randomness. The randomized version uses fresh random bytes instead and ignores `K`. Both versions use the same key format. So in the randomized version, two keys that differ only in `K` give the same signatures when the random bytes are the same (Test 8). You would only notice this if the random number generator were broken.

*My note:* the standardized version, ML-DSA (FIPS 204), always mixes `K` with the fresh random bytes, so this no longer happens.

### 7.3 Public keys that can be changed

In LibOQS 0.4.0, some Rainbow and Falcon public keys could be changed so that an existing signature still verified under the changed key (Test 11). This has since been fixed. The attacker does not get the secret key for the changed public key, so they cannot sign new messages. But a protocol that assumes "this signature belongs to exactly one public key" can be confused. This property is called exclusive ownership ([Pornin and Stern, 2005](https://doi.org/10.1007/11496137_10); [Cremers et al., 2021](https://eprint.iacr.org/2020/1525)). [Jackson et al.](https://eprint.iacr.org/2019/779) showed that such properties can break real protocols.

## 8. Limits of the method

- **It only flips one bit at a time.** Some bugs need two changes together, or a specific value (for example a number exactly equal to the modulus `q`). Single bit flips do not reach them.
- **It starts from one input.** Each test uses one fixed key and one fixed message. A bug that appears only for special keys can be missed. This is why the normal fuzzer found two crashes that these tests missed.
- **It does not check whether the code matches the specification.** For that you still need an independent model of the specification and a comparison of intermediate values.
- **The counts are not bug counts.** They include repeated cases and expected results (Section 5).

So this method does not replace normal fuzzing. It adds a check that normal fuzzing cannot do. Section 9 shows how to close some of these gaps.

## 9. Going further: more relations to test

The paper uses one kind of relation: the output for a changed input must be equal to, or different from, the original output. Many more relations follow the same principle. You still do not need to know the correct output. You only compare outputs with each other.

To find out which relations are worth adding, I looked at the published findings from the first round of China's NGCC competition on [ngcc.dev](https://ngcc.dev/), a public review site run by Markku-Juhani Saarinen (413 findings by October 2026). Several of those bugs are close to what the paper tests, but the paper's tests would not find them. Each subsection below describes one such gap, a published bug that falls into it, and a check that would find it. The finding IDs link to the full reports.

### 9.1 Compare changed outputs with each other, not only with the original

**The gap.** Test 7 only checks that a changed ciphertext gives a key *different from the real key*. But in a KEM with implicit rejection, the key for an invalid ciphertext must also look random. A key that differs from the real key can still be wrong.

**Published bugs.**

- **CheetahKEM** ([kem-09-1](https://ngcc.dev/reports/kem-09.html)) and **LoongKEM** ([kem-18-1](https://ngcc.dev/reports/kem-18.html)): the code that chooses between the real key and the rejection key used a wrong mask. For an invalid ciphertext, it returned a mix of both, so most bits of the real key leaked. The returned key is different from the real key, so Test 7 passes.
- **BAG-Loong** ([kem-03-2](https://ngcc.dev/reports/kem-03.html)), **CheetahKEM** ([kem-09-4](https://ngcc.dev/reports/kem-09.html)) and **DKEM** ([kem-13-1](https://ngcc.dev/reports/kem-13.html), which I reported): the rejection key was computed from only part of the received ciphertext, or from the re-encrypted ciphertext instead of the received one. So different invalid ciphertexts can get the same rejection key. Each one still differs from the real key, so Test 7 passes. In CheetahKEM, this was enough to recover the secret key from decapsulation queries.

**The check.** Collect the keys from all changed ciphertexts and test two rules:

1. **No two changed ciphertexts give the same key.** A collision means the rejection key ignores part of the ciphertext.
2. **No rejection key looks like the real key.** Two unrelated 256-bit keys agree in about half of their bits. If a rejection key agrees with the real key in far more bits, part of the real key is leaking.

This is close to what Mouha et al. originally did for hash functions: they collected all outputs and looked for any collision. The paper compares each output only with the original, because that fits how AFL++ works, and loses this ability.

### 9.2 The return code must not depend on validity

**The gap.** The paper treats the return code as part of the output. For a changed ciphertext, the output is expected to change, so a changed return code passes the test.

**Published bug.** **DTRU** ([kem-14-2](https://ngcc.dev/reports/kem-14.html)): decapsulation returned a different code when it took the implicit-rejection branch. This tells an attacker whether a ciphertext was valid, which is exactly what implicit rejection is meant to hide.

**The check.** For a KEM that claims implicit rejection, the return code for every changed ciphertext must be the same as for the valid ciphertext. For a KEM with explicit rejection, the documentation must say so.

### 9.3 Change values, not only bits

**The gap.** Many encodings store numbers modulo `q` (or a prime `p`). If the decoder accepts `x + q` as another way to write `x`, there are two byte strings for the same value. Flipping one bit changes a number by a power of two, never by exactly `q`, so single bit flips cannot find this.

**Published bugs.** **QIMEN-PIKE** ([kem-31-2](https://ngcc.dev/reports/kem-31.html)): the decoder reduced field elements modulo `p` without rejecting values of `p` or more, so a ciphertext could be changed without changing the key. This broke IND-CCA. **TSUOV** ([sign-31-6](https://ngcc.dev/reports/sign-31.html)) did not reject an unused field value, and **YuanYang.DSA** ([sign-34-2](https://ngcc.dev/reports/sign-34.html)) had public keys with more than one encoding.

**The check.** Describe the input as a list of fields (each field: its bit width and its allowed range), not just as a list of bits. For each field, try the values `q`, `q + 1`, the largest value that fits, and `x + q`. Decoding must either reject the input or give a different output. A simpler and stronger version: decode the input, encode it again, and require the same bytes.

### 9.4 Change every length, in both directions

**The gap.** The paper changes only the signature length, and only to shorter values. KEM functions and key inputs in many APIs also take a length.

**Published bugs.** **DTRU** ([kem-14-1](https://ngcc.dev/reports/kem-14.html)): a caller-declared ciphertext length could overflow a stack buffer in decapsulation. **Rudraksh2** ([kem-34-3](https://ngcc.dev/reports/kem-34.html)): the KEM functions ignored the declared lengths and read past a short buffer. **Tins** ([sign-29-3](https://ngcc.dev/reports/sign-29.html)): an unchecked, too long signature length overflowed a buffer in the verifier.

**The check.** For every length argument, try 0, the correct length minus one, the correct length plus one, and a much larger value. Each call must return an error without crashing. Run these tests with AddressSanitizer, because a short buffer read does not always crash.

### 9.5 Changes that follow the structure of the scheme

**The gap.** Some changes keep the input well formed and only make sense if you know the scheme. Random bit flips almost never produce them.

**Published bugs.**

- **TRINE** ([sign-30-5](https://ngcc.dev/reports/sign-30.html)): each response vector in a signature could be replaced by any nonzero multiple of itself, and the signature still verified.
- **VDOO** ([sign-33-7](https://ngcc.dev/reports/sign-33.html)): in the API format where message and signature are stored together, moving the boundary between them gave a valid signature for a new, shorter or longer message.
- **Galas** ([sign-12-2](https://ngcc.dev/reports/sign-12.html)) and others: the message length was cut to 32 bits before hashing. A message longer than 4 GiB was hashed as a much shorter one, which allowed forgeries.

**The check.** For each scheme, list the transformations that keep the format valid: multiplying a vector by a scalar, negating a value, moving a boundary, very long inputs. Apply each one to a valid signature or ciphertext. The rule is the same as before: a changed input must not verify, or must not give the same key. This needs some knowledge of the scheme, but only a few lines per transformation.

### 9.6 Compare across processes, not only within one

**The gap.** The randomness tests (Tests 2, 5, 10) run inside one process. If an implementation ignores the random bytes it is given and uses its own internal counter instead, keys made one after another in the same process still differ, so the tests pass.

**Published bug.** **HEP-QC** ([kem-17-1](https://ngcc.dev/reports/kem-17.html)): key generation ignored the random number generator provided through the API. Every new process started from the same internal state and produced the same key pair, so anyone could compute the secret key. The ngcc.dev test program checks this by comparing the first key from several new processes.

**The check.** Start two new processes with different random seeds and compare their first key pair, ciphertext, and signature. They must differ.

### 9.7 Compare implementations with each other

**The gap.** The paper tests each implementation on its own. But a scheme often has a reference version and one or more optimized versions, and bugs can sit in only one of them.

**Published bugs.** **FLIT** ([kem-15-1](https://ngcc.dev/reports/kem-15.html)): the reference and optimized FLIT512 code silently derived different keys. **FLIT** ([kem-15-2](https://ngcc.dev/reports/kem-15.html)): only the AVX2 version had a broken comparison that accepted most invalid ciphertexts. **PolarLAC** ([kem-30-3](https://ngcc.dev/reports/kem-30.html)): a ciphertext made by one version could not be decapsulated by the other.

**The check.** Give every version the same inputs, including all the changed inputs from the tests above. All versions must return the same bytes and the same return codes. This needs no knowledge of the correct output at all: the versions check each other.

### 9.8 For hash functions, compare across lengths

**The gap.** Test 1 compares each changed message with the original message of the same length. Some hash bugs only show between messages of different lengths.

**Published bugs.** **Eijen** ([hash-09-1](https://ngcc.dev/reports/hash-09.html)): the empty message and a message of seven zero bits gave the same hash. **MasterCube** ([hash-17-1](https://ngcc.dev/reports/hash-17.html)): a message of 958 one bits and a message of 959 one bits gave the same hash; this happens at every block boundary.

**The check.** Hash many messages of different lengths, especially lengths near byte and block boundaries and messages that differ only by appended zero bits. Look for any two equal hashes. This is the original bit-contribution test of Mouha et al., applied across lengths.

### 9.9 Summary

| Check | What it adds to the paper's tests | Published example | Needs knowledge of the scheme? |
|---|---|---|---|
| Rejection keys compared with each other and with the real key | Finds leaking or non-binding rejection keys | kem-09-1, kem-13-1 | No |
| Return code independent of validity | Finds rejection-branch leaks | kem-14-2 | Only whether rejection is implicit |
| Change field values, re-encode | Finds `x` vs `x + q` duplicates | kem-31-2, sign-31-6 | Field widths and moduli |
| Every length, both directions | Finds ignored or unchecked lengths | kem-14-1, kem-34-3, sign-29-3 | No |
| Structured changes | Finds scalar multiples, boundary shifts, long inputs | sign-30-5, sign-33-7, sign-12-2 | Yes |
| Compare across processes | Finds ignored random number generators | kem-17-1 | No |
| Compare implementations | Finds bugs in only one version | kem-15-1, kem-15-2, kem-30-3 | No |
| Hash collisions across lengths | Finds padding and length bugs | hash-09-1, hash-17-1 | No |

Five of the eight checks need no knowledge of the scheme. They can run automatically on every candidate of a competition, just like the paper's tests.

Here is a sketch of the first check (Section 9.1), as an addition to the Test 7 program in Section 10.2. Like that program, it has not been compiled against a specific liboqs version.

```c
/* Section 9.1: rejection keys from different changed ciphertexts must all
   differ from each other, and none may share too many bits with the real key. */
static int check_rejection_keys(OQS_KEM *kem, uint8_t *c, const uint8_t *sk,
                                const uint8_t *real_key) {
    size_t clen = kem->length_ciphertext, sslen = kem->length_shared_secret;
    size_t n = 8 * clen;                     /* one changed ciphertext per bit */
    uint8_t *keys = malloc(n * sslen);
    int bad = 0;

    for (size_t bit = 0; bit < n; bit++) {
        flip(c, bit);
        OQS_KEM_decaps(kem, keys + bit * sslen, c, sk);
        flip(c, bit);
        size_t same = 0;                     /* bits equal to the real key */
        for (size_t i = 0; i < sslen; i++)
            same += 8 - __builtin_popcount(keys[bit * sslen + i] ^ real_key[i]);
        if (4 * same > 3 * 8 * sslen) {      /* about half is normal */
            printf("bit %zu: rejection key shares %zu bits with the real key\n", bit, same);
            bad++;
        }
    }
    for (size_t i = 0; i < n; i++)
        for (size_t j = i + 1; j < n; j++)
            if (memcmp(keys + i * sslen, keys + j * sslen, sslen) == 0) {
                printf("bits %zu and %zu: same rejection key\n", i, j);
                bad++;
            }
    free(keys);
    return bad;
}
```

## 10. Using it on your own code

### 10.1 Run the authors' code

The [authors' code](https://github.com/jangilcher/cryptoTesting) [source] runs in Docker. `bash run.sh` starts the container. Inside it, `bash reproduce.sh ches_liboqs` repeats the LibOQS 0.14.0 run. Use `cur_liboqs` for 0.8.0, `mid_liboqs` for 0.4.0, `old_liboqs` for 2018, and `supercop` for the hash functions. Add `baseline` to run the normal fuzzer instead.

### 10.2 Write your own Tests 7 and 13

You do not need AFL++ to run the two most important tests. The program below uses the public liboqs API. **It is a sketch: I have not compiled it against a specific liboqs version, so check the API of your version.** Error handling and freeing memory are left out.

```c
#include <oqs/oqs.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Fixed "random" bytes, so every run sees the same keys. */
static uint64_t s = 0x243f6a8885a308d3ULL;
static void fixed_rng(uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        s ^= s << 13; s ^= s >> 7; s ^= s << 17;
        out[i] = (uint8_t)s;
    }
}

static void flip(uint8_t *b, size_t bit) { b[bit / 8] ^= (uint8_t)(1u << (bit % 8)); }

/* Test 7: change one bit of the ciphertext. Layout: guard || c || guard. */
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
        int in_ct = bit >= 8 && bit < 8 * (clen + 1);  /* inside c: key must change */
        flip(buf, bit);
        OQS_STATUS rv1 = OQS_KEM_decaps(kem, ss1, buf + 1, sk);
        int same = rv0 == rv1 && memcmp(ss0, ss1, sslen) == 0;
        if (same == in_ct) {  /* inside c but same key, or guard byte but different key */
            printf("%s: bit %zu: %s\n", name, bit, in_ct ? "malleable ciphertext" : "reads outside c");
            bad++;
        }
        flip(buf, bit);
    }
    OQS_KEM_free(kem);
    return bad;
}

/* Test 13: change the signature length, then one bit of the signature. */
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
    for (size_t len = 0; len <= cap; len++)  /* every other length must fail */
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

Some practical advice:

- Run both tests on every version of your code: the portable reference code and every optimized version (AVX2, AVX-512, embedded). All versions must give the same results on every changed input, including the same return codes.
- The tests also work as a timing check. Run Test 7 under Valgrind with the secret key marked as undefined memory. Valgrind then reports any branch that depends on the secret key. Every changed ciphertext takes the rejection path, which is where FO timing leaks usually are. For a statistical timing check, see [dudect](https://eprint.iacr.org/2016/1123).
- Every API wrapper (NIST API, PQClean API, liboqs) is separate code and needs its own tests. The CROSS bug was only in one wrapper.

### 10.3 How this relates to the NGCC findings

My [earlier post](../pqc-implementation-guide/) sorted the implementation problems found in the first round of China's NGCC competition into nine categories. These tests cover some of them and not others:

| NGCC category | Covered? | Notes |
|---|---|---|
| 2. Wrong FO transform implementation | Yes (Tests 6, 7) | "Compares only every 4th byte" (kem-02-1) is exactly what Test 7 finds |
| 4. Input parsing and memory safety | Yes | Crashes and overflows on changed inputs; guard bytes find over-reads |
| 5. Non-injective encoding | Yes (Tests 7, 11, 13) | The NTRU, Falcon, SNOVA, CROSS kind of bug |
| 3. Randomness problems | Partly (Tests 2, 5, 10) | Finds infinite loops on bad random bytes |
| 1, 6, 7, 8, 9 (security budget, spec mismatch, state, protocol, debug code) | No | These need other checks, such as an independent model of the spec |

## 11. Checklist

Each item comes from a real finding above. They add to sections B, C, and E of the [checklist in my earlier post](../pqc-implementation-guide/).

**Encoding**

- [ ] If data does not fill the last byte, decoding rejects non-zero unused bits (NTRU, SNOVA)
- [ ] Each value has exactly one accepted encoding; "−0" and similar duplicates are rejected (Falcon)
- [ ] Values of `q` or more in a field are rejected (Section 9.3)
- [ ] Decoding and then re-encoding gives the same bytes; otherwise the input is rejected

**Lengths and buffers**

- [ ] Every length argument is checked; a wrong length is rejected (CROSS)
- [ ] Every length argument is tested with 0, one too few, one too many, and a much larger value, under AddressSanitizer (Section 9.4)
- [ ] The output does not depend on bytes outside the input, tested with guard bytes at many lengths (KNOT-384)

**KEMs**

- [ ] Flipping any ciphertext bit changes the key, or gives an error that reveals nothing secret (Test 7)
- [ ] Different invalid ciphertexts give different rejection keys, and no rejection key shares an unusual number of bits with the real key (Section 9.1)
- [ ] With implicit rejection, the return code is the same for valid and invalid ciphertexts (Section 9.2)
- [ ] Decapsulation never crashes or hangs on a changed ciphertext (Big Quake, LEDAkem, LIMA)
- [ ] If decapsulation skips the byte-by-byte re-encryption check, the encoding is checked in another way (NTRU)
- [ ] The documentation says which parts of the secret key are unused for valid ciphertexts (FO `z`)

**Signatures**

- [ ] If the scheme claims strong unforgeability: flipping any signature bit or changing the length makes verification fail (Test 13)
- [ ] A changed public key does not verify existing signatures (Test 11)

**Random numbers and robustness**

- [ ] A broken random number generator leads to an error or a limited number of retries, never an infinite loop (Tests 2, 5, 10)
- [ ] Two new processes with different random seeds produce different keys, ciphertexts, and signatures (Section 9.6)
- [ ] Tests compare return values as well as output bytes

**Process**

- [ ] Tests 7 and 13 run in CI on every version of the code (reference and optimized), with identical results (Section 9.7)
- [ ] Every API wrapper has its own negative tests

## Appendix A. Full results

Results per test and library version (Table 3 of the paper). "Malleable" means the output did not change when it should have. "Over-read" means the output changed when it should not have. Tests with no results are not listed.

| Library | Test | Malleable | Crash / hang | Over-read |
|---|---|---|---|---|
| SUPERCOP 20240107 | 1 | 3 | 0 | 3 |
| LibOQS 0.14.0 | 5 | 1 | 10 hangs | 0 |
| | 6 | 26 | 0 | 0 |
| | 8 | 11 | 0 | 0 |
| | 11 | 10 | 0 | 0 |
| | 13 | 25 | 0 | 0 |
| LibOQS 0.8.0 | 3 | 10 | 0 | 0 |
| | 4 | 10 | 0 | 0 |
| | 5 | 1 | 10 hangs | 0 |
| | 6 | 23 | 0 | 0 |
| | 8 | 3 | 0 | 0 |
| | 13 | 2 | 0 | 0 |
| LibOQS 0.4.0 | 3 | 23 | 8 segfaults | 0 |
| | 4 | 31 | 8 segfaults | 0 |
| | 5 | 1 | 10 hangs | 0 |
| | 6 | 51 | 0 | 0 |
| | 7 | 10 | 0 | 0 |
| | 8 | 10 | 3 heap overflows, 1 hang | 0 |
| | 9 | 0 | 1 hang | 0 |
| | 10 | 22 | 1 hang | 0 |
| | 11 | 7 | 1 hang | 0 |
| | 12 | 0 | 1 hang | 0 |
| | 13 | 9 | 1 hang | 0 |
| LibOQS 2018 | 2 | 3 | 0 | 0 |
| | 3 | 4 | 6 segfaults, 1 error return | 0 |
| | 4 | 9 | 7 segfaults, 1 hang | 0 |
| | 6 | 24 | 12 segfaults, 7 hangs | 0 |
| | 7 | 3 | 9 segfaults, 2 stack overflows, 4 hangs | 0 |
| | 10 | 6 | 0 | 0 |

Normal fuzzer, crashes (hangs in parentheses):

| Library | KEM encaps | KEM decaps | Sign | Verify | Time | Cores |
|---|---|---|---|---|---|---|
| LibOQS 0.14.0 | 0 | 0 | 0 | 0 | 2h | 31 |
| LibOQS 0.8.0 | 0 | 0 | 0 | 0 | 27m | 50 |
| LibOQS 0.4.0 | 8 | 0 | 9 (1) | 0 | 57m | 50 |
| LibOQS 2018 | 10 | 12 (1) | 5 | — | 23m | 75 |
| SUPERCOP (hash) | 4 | | | | 8h 6m | 50 |

## Appendix B. Experiment details

- **Run time of the paper's tests:** LibOQS 0.14.0 12h 40m on 75 cores; 0.8.0 14h 23m on 31 cores; 0.4.0 12h 43m on 31 cores; 2018 8h 59m on 31 cores; SUPERCOP 6h 58m on 31 cores.
- **Machines:** 2× Intel Xeon Gold 6138 (40 cores), 4× Intel Xeon Gold 6252 (96 cores), 1× AMD EPYC 7742 (64 cores).
- **AFL++ settings:** the input size limit was raised from 1 MB to 10 MB because some public keys are large; all built-in input mutations were replaced by the single-bit flip; at most 10 failures were saved per target.
- **Counting:** one result per (scheme, parameter set, library version), even if several inputs trigger it.

## Sources

- Fenzi, Gilcher, Virdia, "Finding Bugs and Features Using Cryptographically-Informed Functional Testing", [TCHES 2026(1), pp. 425–447](https://doi.org/10.46586/tches.v2026.i1.425-447); [ePrint 2024/1122](https://eprint.iacr.org/2024/1122); [code](https://github.com/jangilcher/cryptoTesting) [source]
- Mouha, Raunak, Kuhn, Kacker, "Finding Bugs in Cryptographic Hash Function Implementations", [IEEE Transactions on Reliability 67(3), 2018](https://doi.org/10.1109/TR.2018.2847247)
- Weyuker, "On Testing Non-Testable Programs", [The Computer Journal 25(4), 1982](https://doi.org/10.1093/comjnl/25.4.465)
- Chen, Cheung, Yiu, "Metamorphic Testing: A New Approach for Generating Next Test Cases", [arXiv:2002.12543](https://arxiv.org/abs/2002.12543) (technical report from 1998)
- Chen, Tse, Zhou, "Fault-Based Testing Without the Need of Oracles", [Information and Software Technology 45(1), 2003](https://doi.org/10.1016/S0950-5849%2802%2900129-5)
- Fioraldi, Maier, Eißfeldt, Heuse, "AFL++: Combining Incremental Steps of Fuzzing Research", [USENIX WOOT 2020](https://www.usenix.org/conference/woot20/presentation/fioraldi)
- Gentry, Peikert, Vaikuntanathan, "Trapdoors for Hard Lattices and New Cryptographic Constructions", STOC 2008, [ePrint 2007/432](https://eprint.iacr.org/2007/432)
- Fujisaki, Okamoto, "Secure Integration of Asymmetric and Symmetric Encryption Schemes", [CRYPTO 1999](https://doi.org/10.1007/3-540-48405-1_34)
- Hofheinz, Hövelmanns, Kiltz, "A Modular Analysis of the Fujisaki-Okamoto Transformation", TCC 2017, [ePrint 2017/604](https://eprint.iacr.org/2017/604)
- Pornin, Stern, "Digital Signatures Do Not Guarantee Exclusive Ownership", [ACNS 2005](https://doi.org/10.1007/11496137_10)
- Cremers, Düzlü, Fiedler, Fischlin, Janson, "BUFFing Signature Schemes Beyond Unforgeability and the Case of Post-Quantum Signatures", IEEE S&P 2021, [ePrint 2020/1525](https://eprint.iacr.org/2020/1525)
- Jackson, Cremers, Cohn-Gordon, Sasse, "Seems Legit: Automated Analysis of Subtle Attacks on Protocols that Use Signatures", ACM CCS 2019, [ePrint 2019/779](https://eprint.iacr.org/2019/779)
- Reparaz, Balasch, Verbauwhede, "Dude, is my code constant time?", DATE 2017, [ePrint 2016/1123](https://eprint.iacr.org/2016/1123)
- [NTRU fix: "Ensure trailing bits of ciphertext are 0"](https://github.com/jschanck/ntru/commit/6bb52396fed494001228ca579f4c1d91ef558171) [source]
- [liboqs issue #1315: Malleable Falcon signatures](https://github.com/open-quantum-safe/liboqs/issues/1315) [source]
- [CROSS-lib-oqs issue #1: Potential SUF-CMA violation](https://github.com/CROSS-signature/CROSS-lib-oqs/issues/1) [source]
- [ngcc.dev](https://ngcc.dev/), public review of the NGCC Round 1 candidates (findings cited in Section 9 accessed 2026-10-21); [reproduction harness](https://github.com/ngcc-dev/ngcc-harness) [source]
- [FIPS 203 (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final) and [FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final)
