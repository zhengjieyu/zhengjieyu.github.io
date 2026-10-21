# Flip One Bit: Testing Cryptographic Code Without Knowing the Right Answer

*For anyone who writes or tests cryptographic code · ~15 min read · October 21, 2026*

In 2020, the NTRU code in LibOQS had a small bug. LibOQS is a widely used C library of post-quantum algorithms, and NTRU is one of the key encapsulation mechanisms (KEMs) it shipped. The last byte of an NTRU ciphertext has four bits that carry no data. The decapsulation code never looked at them. So you could flip one of those bits, hand the changed ciphertext to decapsulation, and get back the original shared key.

That sounds harmless, but it breaks the main security promise of the KEM. And no test caught it. The code passed its known-answer tests, it never crashed, and AddressSanitizer reported nothing.

A TCHES 2026 paper by Giacomo Fenzi, Jan Gilcher, and Fernando Virdia ([paper](https://doi.org/10.46586/tches.v2026.i1.425-447), [code](https://github.com/jangilcher/cryptoTesting)) describes a simple way to find bugs like this automatically. This post explains the idea, walks through some of the bugs it found, and then goes a step further: using bugs from the public review of China's NGCC competition, I look at what the method misses and which extra checks would catch those cases.

> **In one sentence:** take a valid input, flip one bit, and check that the output changes when it should and stays the same when it should not.

## 1. Why cryptographic code is hard to test

Most code is tested by comparing its output with an answer you already know. For cryptographic code, that is surprisingly hard.

The usual tool is a known-answer test (KAT): run the code on a fixed list of inputs and compare the outputs with stored values. But those stored values come from the reference implementation, which is itself just code. If the reference has a bug, the KATs have it too. And KATs only use valid inputs. A bug that only shows up for a slightly broken ciphertext is never exercised.

Sanitizers such as AddressSanitizer catch reads and writes outside allocated memory. Fuzzers such as [AFL++](https://www.usenix.org/conference/woot20/presentation/fioraldi) feed the program many random inputs and record crashes. Both are useful. But the NTRU bug did not touch any bad memory and did not crash. It just returned the wrong answer, and the wrong answer looked like a normal key.

The deeper problem is that cryptographic outputs are designed to look random. If a test sees the key `3f a1 9c ...`, it has no way to tell whether that key is right. Software testing calls this the **oracle problem** ([Weyuker, 1982](https://doi.org/10.1093/comjnl/25.4.465)): you have no "oracle" that tells you whether an output is correct.

## 2. The trick: compare two outputs

You often cannot say whether one output is correct. But you can often say how two outputs should relate to each other. This is called **metamorphic testing** ([Chen, Cheung, Yiu, 1998](https://arxiv.org/abs/2002.12543); [Chen, Tse, Zhou, 2003](https://doi.org/10.1016/S0950-5849%2802%2900129-5)).

Take a hash function. You do not know what `H(x)` should be. But you do know two things. First, every bit of the message should matter: if you flip any bit, the hash must change. Second, nothing outside the message should matter: if you change the byte right after the message in memory, the hash must stay the same.

Each of these gives you a test that needs no known answer. Flip one bit, hash again, compare.

This idea is not new. In 2018, [Mouha, Raunak, Kuhn, and Kacker](https://doi.org/10.1109/TR.2018.2847247) ran exactly these two checks on the 86 reference implementations submitted to the SHA-3 competition. 19 of them ignored some input bit. 17 of them read past the end of the message. Two of the five SHA-3 finalists were among them.

To check the second rule, the test puts one extra byte before the input and one after it, called **guard bytes**, and passes the function a pointer to the real input in between. If flipping a guard byte changes the output, the function is reading memory it should not. Here is what that looks like for a KEM ciphertext:

![Test 7 buffer layout: a guard byte, the ciphertext marked DIFF including the last byte's padding bits, and a trailing guard byte; flipping the guard must leave the output unchanged, flipping any ciphertext bit must change it](./diagrams/buffer-layout.svg)

Every bit of the ciphertext, including the padding bits, must change the output. The guard bytes must not. The NTRU bug is the orange part of the picture.

Guard bytes catch something that sanitizers miss. A sanitizer only complains when code touches memory that was never allocated. If the code reads the next byte of a larger, valid buffer, the sanitizer sees nothing wrong.

## 3. Security definitions are already test rules

The new paper applies the same idea to KEMs and digital signatures. The key observation is that their security definitions translate directly into rules you can test.

Start with **IND-CCA**, the standard security goal for a KEM. Informally, it says that an attacker may ask the system to decapsulate any ciphertext they like, except the one they are attacking, and still learn nothing about the key inside that one.

Now suppose that flipping one bit of a ciphertext gives the same key. The attacker takes the target ciphertext, flips a bit, and asks for that one to be decapsulated. This is allowed, because it is a different ciphertext. The system returns the key, and the attacker has the target key. That is the NTRU bug, and it is a complete break.

So IND-CCA gives a simple rule: **flip any bit of a valid ciphertext, decapsulate it, and the key must be different.**

Signatures work the same way. The usual goal is that nobody can sign a new message. A stronger goal, **strong unforgeability** (sUF-CMA), also says that nobody can produce a second, different signature for a message that was already signed. Some protocols rely on this, for example when they use a signature as a unique ID. The rule here is: **flip any bit of a valid signature, or change its length, and verification must fail.** NIST did not require strong unforgeability, so for some schemes a failure here is just information. For others, as we will see, it is a real bug.

## 4. What the test program does

Every test follows the same five steps:

1. Make a valid input, for example a key pair and a ciphertext.
2. Compute the normal output, for example the decapsulated key.
3. Flip one bit of the input.
4. Compute the output again.
5. Check whether the output changed or stayed the same, as the rules require. If not, crash on purpose.

Steps 3 to 5 repeat for every bit. The program crashes on purpose so that a fuzzer like AFL++ saves the input that caused the problem. AFL++ is used here only to run many tests in parallel and to store the failures; its usual input mutations are switched off.

![The Test loop: GenInput produces a baseline, Maul flips one bit and states the expectation, Call reruns the function, Match aborts on a mismatch, and AFL++ stores the crashing input](./diagrams/test-loop.svg)

Before flipping single bits, the test also tries the input unchanged, all zeros, and all ones. The paper names the four parts of the loop `GenInput`, `Maul` ("damage"), `Call`, and `Match`. Only `Call` depends on the algorithm being tested, so the same code works for every scheme in a library.

The paper runs this loop on every input of every function: hashes, key generation, encapsulation, decapsulation, signing, and verification, 13 tests in total. Two details are worth mentioning. Where a function uses random bytes, the test fixes them so the results are repeatable, and it also tries a broken random generator that returns the same byte forever (some implementations then loop forever). And where a signature has a variable length, the test changes the length field too.

The two most important tests are the ones from Section 3: changing the ciphertext before decapsulation (Test 7) and changing the signature before verification (Test 13).

## 5. What they found

The authors ran the tests on four versions of LibOQS, from 2018, 2020, 2023, and 2025, and on the hash functions in SUPERCOP, a benchmarking suite with many implementations. They used old versions on purpose: LibOQS drops schemes that leave the NIST competition, so only old versions still contain them. A full run takes about half a day on a server.

To see what the new tests add, they also ran a normal fuzzer on the same code:

| LibOQS version | Normal fuzzer | Additional findings from the new tests |
|---|---|---|
| 2018 | 27 crashes, 1 hang | 3 IND-CCA breaks |
| 0.4.0 (2020) | 17 crashes, 1 hang | 10 IND-CCA breaks, 9 sUF-CMA breaks, 3 buffer overflows |
| 0.8.0 (2023) | nothing | 2 sUF-CMA breaks |
| 0.14.0 (2025) | nothing | 25 sUF-CMA breaks |

The last two rows are the interesting ones. On recent versions, the normal fuzzer finds nothing at all, while the new tests still find dozens of problems. The new tests also found almost every crash the fuzzer found. The exceptions were two crashes, in Dilithium III and Picnic_L3_UR, that only the fuzzer found.

These numbers count each scheme, parameter set, and library version separately, so they are not counts of distinct bugs. And as Section 7 explains, not every result is a bug.

## 6. A few of the bugs

Most of the real bugs have the same root cause: **one value could be written as more than one byte string, and the code accepted all of them.**

**NTRU.** This is the bug from the start of the post. NTRU ciphertexts store numbers of 11 or 13 bits. For the three affected parameter sets the total is not a multiple of 8 (for example, 508 × 11 = 5588 bits), so the last byte has 4 unused bits. The specification says they are zero, but decapsulation never checked. The [fix](https://github.com/jschanck/ntru/commit/6bb52396fed494001228ca579f4c1d91ef558171) is one line:

```c
/* Check that unused bits of last byte of ciphertext are zero */
fail |= c[NTRU_CIPHERTEXTBYTES-1] & (0xff << (8 - (7 & (NTRU_LOGQ*NTRU_PACK_DEG))));
```

Many KEMs re-encrypt during decapsulation and compare the result with the received ciphertext byte by byte, which would have caught this. I think the reason NTRU missed it is that it does not re-encrypt. It checks the decoded numbers directly, and the unused bits are already gone by then.

**SNOVA**, a newer signature candidate, had the same problem in the last byte of some signatures.

**Falcon.** Falcon stores each number in a signature as a sign bit plus the size of the number. The decoder accepted "negative zero", a sign bit of 1 with size zero, as another way to write zero. It also did not check that the padding at the end was zero ([liboqs issue #1315](https://github.com/open-quantum-safe/liboqs/issues/1315)). So one signature could be written in several ways. This matters because Falcon is built on the [GPV framework](https://eprint.iacr.org/2007/432), which normally gives strong unforgeability, and users had good reason to expect it. The Falcon team fixed it in version 1.2 of the specification.

**CROSS.** The verification function of CROSS received the signature length but ignored it, because CROSS signatures have a fixed length. So you could append any bytes to a valid signature and it still verified ([issue](https://github.com/CROSS-signature/CROSS-lib-oqs/issues/1)). This was only in the version written for the PQClean API; the version submitted to NIST checked the length.

**KNOT-384.** This one is a hash function. For messages whose length is a multiple of 6 bytes, the optimized code read one byte past the end of the message, so the hash depended on whatever was next in memory. The guard byte found it.

One more finding is worth a mention. In the 2018 version, three KEMs crashed or hung when given a changed ciphertext. A crash looks like a robustness problem, but an attacker can see it, and it tells them "this ciphertext was invalid". Attacks on KEMs can use exactly that kind of yes/no answer to recover the secret key.

## 7. When a result is not a bug

Some results are not mistakes at all. They come from how the schemes are designed. The paper calls these "features", and they are worth knowing about.

The clearest case is in the secret key of most post-quantum KEMs, including ML-KEM. These KEMs reach IND-CCA security with the [Fujisaki–Okamoto (FO) transform](https://doi.org/10.1007/3-540-48405-1_34). In its usual "implicit rejection" form ([Hofheinz, Hövelmanns, Kiltz](https://eprint.iacr.org/2017/604)), the secret key contains a random value `z`. When a ciphertext is invalid, the KEM does not return an error. It returns a fake key derived from `z` instead.

![FO implicit rejection: for a valid ciphertext the output key comes from G(m' || h), and the rejection key J(z || c) is computed but discarded, so changing z does not change the output](./diagrams/fo-implicit-rejection.svg)

For a valid ciphertext, the fake key is still computed, so that both cases take the same time, and then thrown away. So if you change `z`, decapsulation of a valid ciphertext still returns the right key. The test that changes the secret key (Test 6) reports this for almost every KEM. It is not a bug. But imagine a system that checks a stored secret key by decapsulating one valid ciphertext. A key with a damaged `z` would pass, and the damage would only show later.

Randomized Dilithium has a similar property. Its secret key contains a value `K` that only the deterministic version uses, so two keys that differ only in `K` sign identically. ML-DSA, the standardized version, now mixes `K` into every signature. And in the 2020 version of LibOQS, some Rainbow and Falcon public keys could be modified so that an old signature still verified under the new key. This is a property called exclusive ownership ([Pornin and Stern](https://doi.org/10.1007/11496137_10); [Cremers et al.](https://eprint.iacr.org/2020/1525)), and [Jackson et al.](https://eprint.iacr.org/2019/779) showed that protocols can break when it is missing.

## 8. Going further: what single bit flips miss

The method is simple, and that is also its limit. It flips one bit at a time, starts from one fixed input, and compares each output only with the original one.

To see what that misses, I went through the published findings from the first round of China's NGCC competition on [ngcc.dev](https://ngcc.dev/), a public review site run by Markku-Juhani Saarinen. Several of the bugs there are of exactly the kind this paper looks for, but its tests would not find them. Each one suggests one more rule. None of these rules needs a known answer either.

**Compare changed outputs with each other, not only with the original.** Test 7 checks that a changed ciphertext gives a key different from the real one. But in CheetahKEM and LoongKEM ([kem-09-1](https://ngcc.dev/reports/kem-09.html), [kem-18-1](https://ngcc.dev/reports/kem-18.html)), a wrong mask made the returned key a mix of the fake key and the real key, so most of the real key leaked. In DKEM ([kem-13-1](https://ngcc.dev/reports/kem-13.html), which I reported) and BAG-Loong ([kem-03-2](https://ngcc.dev/reports/kem-03.html)), the fake key did not depend on the whole ciphertext, so different invalid ciphertexts got the same fake key. In all these cases the returned key differs from the real one, so Test 7 passes. The fix is to collect the keys from all changed ciphertexts and check two more things: no two are equal, and none shares far more than half its bits with the real key. Mouha et al. originally compared all outputs with each other; the paper dropped this to fit how AFL++ works.

**The return code must not reveal anything.** DTRU ([kem-14-2](https://ngcc.dev/reports/kem-14.html)) returned a different code when it took the rejection path. That tells an attacker whether a ciphertext was valid, which is exactly what implicit rejection is meant to hide. The paper treats the return code as part of the output, and the output is expected to change, so it misses this. The rule: with implicit rejection, the return code is the same for every ciphertext.

**Change values, not just bits.** Many formats store numbers modulo some `q`. If the decoder accepts `x + q` as another way to write `x`, you again have two byte strings for one value. But flipping one bit changes a number by a power of two, never by exactly `q`, so bit flips cannot find this. QIMEN-PIKE ([kem-31-2](https://ngcc.dev/reports/kem-31.html)) lost IND-CCA this way. The simplest check is to decode the input, encode it again, and require the same bytes.

**Change every length, in both directions.** The paper only shortens the signature length. DTRU ([kem-14-1](https://ngcc.dev/reports/kem-14.html)) overflowed a stack buffer when given a wrong ciphertext length, and Tins ([sign-29-3](https://ngcc.dev/reports/sign-29.html)) overflowed a buffer when given a signature length that was too long. Every length argument should be tried shorter and longer, under AddressSanitizer.

**Compare across processes.** HEP-QC ([kem-17-1](https://ngcc.dev/reports/kem-17.html)) ignored the random generator it was given and used its own, which started from the same state in every process. Within one process the keys still differed, so a test inside one process would pass. Every new process produced the same key pair, though, so anyone could compute the secret key. Comparing the first key from two fresh processes finds this.

**Compare implementations.** A scheme often has a reference version and an optimized version. In FLIT ([kem-15-1](https://ngcc.dev/reports/kem-15.html), [kem-15-2](https://ngcc.dev/reports/kem-15.html)), the two derived different keys, and only the AVX2 version accepted most invalid ciphertexts. Running every changed input through every version and requiring identical results finds such bugs without knowing any correct answer.

**Some changes need knowledge of the scheme.** In TRINE ([sign-30-5](https://ngcc.dev/reports/sign-30.html)), multiplying parts of a signature by a scalar gave another valid signature. In VDOO ([sign-33-7](https://ngcc.dev/reports/sign-33.html)), moving the boundary between message and signature in the combined format gave a valid signature for a new message. Random bit flips will almost never produce these changes, but once you know the structure, each one is a few lines of test code.

**For hash functions, compare different lengths.** In Eijen ([hash-09-1](https://ngcc.dev/reports/hash-09.html)), the empty message and a message of seven zero bits had the same hash. Only a test that compares messages of different lengths can see that.

Most of these extra rules need no knowledge of the scheme at all. Like the paper's tests, they can run automatically on every candidate in a competition.

## 9. Trying it yourself

The authors' code runs in Docker: `bash run.sh` starts a container, and `bash reproduce.sh ches_liboqs` repeats their LibOQS 0.14.0 run.

But you do not need their setup to run the most important test on your own code. Here is Test 7 for any KEM in liboqs, with the guard bytes from Section 2. Error handling is left out to keep it short.

```c
#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void flip(uint8_t *b, size_t bit) { b[bit / 8] ^= (uint8_t)(1u << (bit % 8)); }

/* Flip every bit of a valid ciphertext and of the guard byte on each side. */
static int test_decaps_ct(const char *name) {
    OQS_KEM *kem = OQS_KEM_new(name);
    size_t clen = kem->length_ciphertext, sslen = kem->length_shared_secret;
    uint8_t *pk = malloc(kem->length_public_key), *sk = malloc(kem->length_secret_key);
    uint8_t *buf = malloc(clen + 2), *ss = malloc(sslen);
    uint8_t *ss0 = malloc(sslen), *ss1 = malloc(sslen);

    OQS_KEM_keypair(kem, pk, sk);
    buf[0] = buf[clen + 1] = 0xFF;                 /* guard bytes */
    OQS_KEM_encaps(kem, buf + 1, ss, pk);
    OQS_STATUS rv0 = OQS_KEM_decaps(kem, ss0, buf + 1, sk);

    int bad = 0;
    for (size_t bit = 0; bit < 8 * (clen + 2); bit++) {
        int in_ct = bit >= 8 && bit < 8 * (clen + 1);  /* inside c: key must change */
        flip(buf, bit);
        OQS_STATUS rv1 = OQS_KEM_decaps(kem, ss1, buf + 1, sk);
        int same = rv0 == rv1 && memcmp(ss0, ss1, sslen) == 0;
        if (same == in_ct) {
            printf("%s: bit %zu: %s\n", name, bit, in_ct ? "same key" : "reads outside c");
            bad++;
        }
        flip(buf, bit);
    }
    OQS_KEM_free(kem);
    return bad;
}

int main(int argc, char **argv) {
    OQS_init();
    return argc == 2 ? test_decaps_ct(argv[1]) != 0 : 2;
}
```

The signature version is the same loop around `OQS_SIG_verify`, plus a second loop that tries every wrong length. To add the first extra rule from Section 8, keep the keys from all the changed ciphertexts and compare them with each other.

If you only take a few things from this post, I would suggest these:

- Whenever data does not fill its last byte, check that the unused bits are zero.
- Accept exactly one encoding for every value. Decode, encode again, and compare.
- Check every length argument, in both directions.
- Run Test 7 and Test 13 on every version of your code, reference and optimized, and require identical results.

My [earlier post on engineering PQC implementations](../pqc-implementation-guide/) has a longer checklist, and these tests cover several of its items.

## Sources

- Fenzi, Gilcher, Virdia, "Finding Bugs and Features Using Cryptographically-Informed Functional Testing", [TCHES 2026(1), pp. 425–447](https://doi.org/10.46586/tches.v2026.i1.425-447); [ePrint 2024/1122](https://eprint.iacr.org/2024/1122); [code](https://github.com/jangilcher/cryptoTesting). Table 3 of the paper has the full results per test and version.
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
- [NTRU fix: "Ensure trailing bits of ciphertext are 0"](https://github.com/jschanck/ntru/commit/6bb52396fed494001228ca579f4c1d91ef558171)
- [liboqs issue #1315: Malleable Falcon signatures](https://github.com/open-quantum-safe/liboqs/issues/1315)
- [CROSS-lib-oqs issue #1: Potential SUF-CMA violation](https://github.com/CROSS-signature/CROSS-lib-oqs/issues/1)
- [ngcc.dev](https://ngcc.dev/), public review of the NGCC Round 1 candidates (findings cited in Section 8 accessed 2026-10-21)
