Post-quantum cryptography: breakthroughs
========================================

.. include:: /_generated/nav/pqc.rst

.. epigraph::

   "A digital computer is generally believed to be an efficient universal
   computing device; that is, it is believed able to simulate any physical
   computing device with an increase in computation time by at most a
   polynomial factor. This may not be true when quantum mechanics is taken
   into consideration."
   -- Peter Shor, *Polynomial-Time Algorithms for Prime Factorization and
   Discrete Logarithms on a Quantum Computer*, 1997

Public-key cryptography rests on problems believed to be hard: factoring and
discrete logarithms for RSA, Diffie-Hellman and elliptic curves. Shor's 1994
algorithm solves both on a quantum computer, and Grover's search halves the
security of every symmetric key and hash. Post-quantum cryptography looks for
problems that resist both: short vectors in lattices, decoding random linear
codes, solving systems of quadratic equations, and inverting hash functions.
Most of those ideas are older than the threat, and several schemes on this
page fell to classical attacks long before a quantum computer could matter.

This chronology traces the ideas behind :mod:`cybersecuritykit.pqc`, from
Prange's information-set decoding of 1962 to the standards NIST published in
2024 and Beullens's break of Rainbow. Vectors and matrices have integer
entries modulo :math:`q`, written :math:`\mathbb{Z}_q`, with
:math:`a \bmod q` as ``a % q``; :math:`R_q = \mathbb{Z}_q[x]/(x^n + 1)` is
the ring of the ring-based schemes, and :math:`\mathrm{GF}(2)` is the field of
bits. Each entry states the problem, gives the mechanism and its key
equation, and links the code and a gallery example that reproduce it. The
quantum algorithms run on a small state-vector simulator, and the keys,
codes and fields are small and the searches bounded, so every example runs
in seconds. Topics shared with blockchainkit, `Lamport signatures
<https://cpoli.github.io/blockchainkit/history/crypto_breakthroughs.html#lamport-s-one-time-signatures-from-a-hash>`__
and `Merkle trees
<https://cpoli.github.io/blockchainkit/history/structures_breakthroughs.html#merkle-trees-and-compact-authentication>`__,
are taught there in full and only summarized here. Isogeny-based schemes are
left out: the 2022 break of SIKE is mentioned in the Rainbow entry, but a
faithful toy of it would need more machinery than the rest of the page.

.. contents:: Timeline
   :local:
   :depth: 1

1962 -- Prange's information-set decoding
-----------------------------------------

Every code-based cryptosystem rests on one hard problem: given a parity-check
matrix :math:`H` of size :math:`r \times n` with :math:`r = n - k`, and a
syndrome :math:`s`, find an error :math:`e` of weight at most :math:`t` with
:math:`He = s`. Eugene Prange, working on cyclic codes at the Air Force
Cambridge Research Laboratories, proposed guessing. Choose :math:`r` columns
at random. If the whole error lies in them and they are invertible, one
Gaussian elimination recovers :math:`e`. A guess holds the error with
probability

.. math::

   p = \binom{n - t}{r - t} \Big/ \binom{n}{r} = \binom{n - t}{k} \Big/ \binom{n}{k},

so the number of guesses is geometric with mean about :math:`1/p`. Stern
(1988) and every later information-set decoder refine this loop, and every
McEliece parameter set is sized against its cost.

*Implementation:* :func:`cybersecuritykit.pqc.systems.isd.prange_isd` runs the
loop on bitmask rows over GF(2), and
:func:`cybersecuritykit.pqc.systems.isd.prange_success_probability` gives
:math:`p`. The toy codes have :math:`n \le 32`. Singular column sets count as
failed guesses, so the observed mean is about :math:`1/(0.29\,p)` rather than
:math:`1/p`.

*References:* E. Prange, "The use of information sets in decoding cyclic
codes", *IRE Transactions on Information Theory* 8(5), S5–S9 (1962).
`DOI <https://doi.org/10.1109/TIT.1962.1057777>`__.

.. minigallery:: ../../examples/pqc/codes/plot_30_prange_isd.py

1978 -- McEliece's code-based cryptosystem
------------------------------------------

Robert McEliece of the Jet Propulsion Laboratory built a public-key system
from error-correcting codes the year after RSA. The private key is a binary
Goppa code with generator :math:`G`, which its owner can decode quickly. The
public key hides it behind a random invertible :math:`S` and a permutation
:math:`P`:

.. math::

   G' = S\,G\,P, \qquad c = m\,G' + e, \quad \operatorname{wt}(e) = t.

The owner undoes :math:`P`, removes the :math:`t` errors with the Goppa
decoder and undoes :math:`S`. An attacker sees what looks like a random code
and must run information-set decoding. The original parameters
(:math:`n = 1024`, :math:`k = 524`, :math:`t = 50`) have never been broken
structurally. Their cost is the key size, which is why Classic McEliece, the
direct descendant, has public keys of hundreds of kilobytes.

*Implementation:* :func:`cybersecuritykit.pqc.systems.mceliece.goppa_code`,
:func:`cybersecuritykit.pqc.systems.mceliece.mceliece_keygen`,
:func:`cybersecuritykit.pqc.systems.mceliece.mceliece_encrypt` and
:func:`cybersecuritykit.pqc.systems.mceliece.mceliece_decrypt` implement the
scheme, and :func:`cybersecuritykit.pqc.systems.mceliece.break_mceliece`
breaks it with Prange's decoder. The codes live over :math:`\mathrm{GF}(2^m)`
with :math:`m \le 12`. Decoding solves the key equation with the extended
Euclidean algorithm on :math:`g^2` (Sugiyama et al.) instead of Patterson's
algorithm.

*References:* R. J. McEliece, "A public-key cryptosystem based on algebraic
coding theory", *DSN Progress Report* 42-44, 114–116 (1978).
`PDF <https://ipnpr.jpl.nasa.gov/progress_report2/42-44/44N.PDF>`__.

.. minigallery:: ../../examples/pqc/codes/plot_31_mceliece.py

1979 -- Winternitz one-time signatures
--------------------------------------

Lamport's one-time signature, taught in `blockchainkit's Lamport entry
<https://cpoli.github.io/blockchainkit/history/crypto_breakthroughs.html#lamport-s-one-time-signatures-from-a-hash>`__,
publishes two hashes per message bit and reveals one secret per bit, so a
256-bit digest costs 256 revealed secrets. Robert Winternitz suggested to
Ralph Merkle a way to sign several bits with one secret. This entry goes
beyond the Lamport entry. Write the digest in base :math:`w` as digits
:math:`d_1, \dots, d_\ell`. For each digit, hash a secret :math:`s_i` along a
`hash chain
<https://cpoli.github.io/blockchainkit/history/structures_breakthroughs.html#lamport-s-hash-chains-and-one-time-passwords>`__
of length :math:`w - 1` whose end :math:`p_i` is public, and reveal the value
:math:`d_i` steps along it:

.. math::

   \sigma_i = H^{d_i}(s_i), \qquad H^{\,w-1-d_i}(\sigma_i) = p_i,
   \qquad C = \sum_{i=1}^{\ell} (w - 1 - d_i).

Anyone can hash a revealed value further, which would raise a digit, so the
checksum :math:`C` is signed too. Raising a message digit lowers :math:`C`,
which would mean walking a checksum chain backwards. A larger :math:`w` gives
fewer chains and a shorter signature but more hashing, and the key is still
one-time: two signatures reveal the lower of two values on every chain.

*Implementation:* :func:`cybersecuritykit.pqc.systems.winternitz.winternitz_sign`
and :func:`cybersecuritykit.pqc.systems.winternitz.winternitz_verify` follow
the WOTS+ chain of RFC 8391, with hashes keyed by a public seed and a chain
address, over 2- to 32-byte truncated SHA-256 rather than full-width hashes;
:func:`cybersecuritykit.pqc.systems.winternitz.winternitz_cost` gives the
size-against-work trade-off, and
:func:`cybersecuritykit.pqc.systems.winternitz.winternitz_forge` turns several
signatures under one key into a forgery.

*References:* R. C. Merkle, "A certified digital signature", *Advances in
Cryptology -- CRYPTO '89*, LNCS 435, 218–238 (1990).
`DOI <https://doi.org/10.1007/0-387-34805-0_21>`__. A. Hülsing, "W-OTS+ --
shorter signatures for hash-based signature schemes", *AFRICACRYPT 2013*, LNCS
7918, 173–188 (2013). `DOI <https://doi.org/10.1007/978-3-642-38553-7_10>`__.

.. minigallery:: ../../examples/pqc/hash_signatures/plot_60_winternitz_signatures.py

1982 -- The LLL lattice-reduction algorithm
-------------------------------------------

Arjen Lenstra, Hendrik Lenstra and László Lovász needed short vectors in
integer lattices to factor polynomials with rational coefficients. A lattice
has infinitely many bases, and a random one is long and nearly parallel.
Their algorithm alternates two steps: size-reduce each vector by subtracting
integer multiples of the earlier ones, and swap two neighbours whenever the
Gram-Schmidt length drops too fast, as measured by the Lovász condition:

.. math::

   \|b_k^*\|^2 \ge \left(\delta - \mu_{k,k-1}^2\right) \|b_{k-1}^*\|^2,
   \qquad \delta = \tfrac{3}{4}, \qquad
   \|b_1\| \le 2^{(n-1)/2} \lambda_1(L).

It runs in polynomial time and returns a first vector within an exponential
factor of the shortest. That factor is useless against cryptographic
dimensions but decisive in small ones, and LLL with its block descendants is
the yardstick against which every lattice scheme sets its parameters.

*Implementation:* :func:`cybersecuritykit.pqc.systems.lattice.lll_reduce`
keeps the Gram-Schmidt data as exact fractions and updates it on each swap
(Cohen's Algorithm 2.6.3), so it is exact but slow beyond a few dozen
dimensions; production reducers use floating point and BKZ.

*References:* A. K. Lenstra, H. W. Lenstra Jr. and L. Lovász, "Factoring
polynomials with rational coefficients", *Mathematische Annalen* 261,
515–534 (1982). `DOI <https://doi.org/10.1007/BF01457454>`__.

.. minigallery:: ../../examples/pqc/lattices/plot_01_lll_reduction.py

1986 -- Niederreiter's syndrome cryptosystem
--------------------------------------------

Harald Niederreiter swapped the roles of message and noise. The plaintext is
encoded as an error vector :math:`e` of weight :math:`t`, and the ciphertext
is its syndrome under a scrambled parity-check matrix:

.. math::

   H' = S\,H\,P, \qquad c = H' e^{\mathsf T}.

The ciphertext has only :math:`n - k` bits, and the public key can be given
in systematic form. Niederreiter proposed generalized Reed-Solomon codes,
whose structure Sidelnikov and Shestakov recovered in 1992. With Goppa codes
the scheme is exactly as hard as McEliece (Li, Deng and Wang, 1994), and
Classic McEliece today is in fact its Niederreiter form.

*Implementation:* :func:`cybersecuritykit.pqc.systems.mceliece.niederreiter_keygen`,
:func:`cybersecuritykit.pqc.systems.mceliece.niederreiter_encrypt` and
:func:`cybersecuritykit.pqc.systems.mceliece.niederreiter_decrypt` reuse the
toy Goppa codes, and
:func:`cybersecuritykit.pqc.systems.mceliece.break_niederreiter` recovers the
error with Prange's decoder. Encoding arbitrary messages into weight-:math:`t`
vectors is left out; the plaintext is the error vector itself.

*References:* H. Niederreiter, "Knapsack-type cryptosystems and algebraic
coding theory", *Problems of Control and Information Theory* 15(2) (1986).

.. minigallery:: ../../examples/pqc/codes/plot_32_niederreiter.py

1988 -- Matsumoto-Imai's C* and Patarin's linearization (1995)
--------------------------------------------------------------

Tsutomu Matsumoto and Hideki Imai proposed the first multivariate public-key
scheme. Identify :math:`\mathrm{GF}(2)^n` with :math:`\mathrm{GF}(2^n)` and
take the power map :math:`F(X) = X^{2^\theta + 1}`. As a product of two
Frobenius powers its coordinates are quadratic over :math:`\mathrm{GF}(2)`,
and it is a bijection when :math:`\gcd(2^\theta + 1, 2^n - 1) = 1`. Hidden
between secret affine maps, :math:`P = T \circ F \circ S` is :math:`n`
quadratic polynomials in :math:`n` bits. Jacques Patarin broke it in 1995.
From :math:`Y = X^{2^\theta + 1}`,

.. math::

   X \, Y^{2^\theta} = X^{2^{2\theta}} \, Y,

and both sides are bilinear in the bits of :math:`X` and :math:`Y`. Through
:math:`S` and :math:`T` this gives relations
:math:`\sum \gamma_{ij} u_i v_j + \sum \alpha_i u_i + \sum \beta_j v_j + \delta = 0`
between every plaintext :math:`u` and its ciphertext :math:`v`. Pairs computed
with the public key reveal the relations. A target ciphertext then turns them
into a linear system for its plaintext.

*Implementation:* :func:`cybersecuritykit.pqc.systems.multivariate.matsumoto_imai_keygen`,
:func:`cybersecuritykit.pqc.systems.multivariate.matsumoto_imai_encrypt` and
:func:`cybersecuritykit.pqc.systems.multivariate.matsumoto_imai_decrypt` build
the scheme for :math:`n \le 12` bits, and
:func:`cybersecuritykit.pqc.systems.multivariate.patarin_linearization` runs
the attack from about :math:`2(n+1)^2` pairs. The final candidates are checked
by brute force over the small solution space.

*References:* T. Matsumoto and H. Imai, "Public quadratic polynomial-tuples for
efficient signature-verification and message-encryption", *EUROCRYPT '88*,
LNCS 330, 419–453 (1988). `DOI <https://doi.org/10.1007/3-540-45961-8_39>`__.
J. Patarin, "Cryptanalysis of the Matsumoto and Imai public key scheme of
Eurocrypt'88", *CRYPTO '95*, LNCS 963, 248–261 (1995).
`DOI <https://doi.org/10.1007/3-540-44750-4_20>`__.

.. minigallery:: ../../examples/pqc/multivariate/plot_33_matsumoto_imai_patarin.py

1994 -- Shor's period finding
-----------------------------

Factoring :math:`N` reduces to finding the order :math:`r` of a random base
:math:`a` modulo :math:`N`: if :math:`r` is even and
:math:`a^{r/2} \not\equiv -1`, the gcds of :math:`a^{r/2} \pm 1` with
:math:`N` are factors. Peter Shor showed a quantum computer finds :math:`r`
in polynomial time. It puts a register of :math:`Q = 2^q \ge N^2` values in
superposition, computes :math:`a^x \bmod N` into a second register, and
applies the quantum Fourier transform to the first, whose measurement lands
near a multiple of :math:`Q / r`:

.. math::

   \Pr[y] = \frac{1}{Q^2} \sum_{c} \Bigl| \sum_{x : a^x \equiv c}
   e^{2 \pi i x y / Q} \Bigr|^2, \qquad \Bigl| \frac{y}{Q} - \frac{k}{r} \Bigr|
   \le \frac{1}{2Q}.

Continued fractions recover :math:`k / r`. The same method solves discrete
logarithms in any group, so RSA, Diffie-Hellman and elliptic-curve
cryptography all fall to a large quantum computer, which is the reason
post-quantum cryptography exists.

*Implementation:* :func:`cybersecuritykit.pqc.systems.shor.shor_factor` and
:func:`cybersecuritykit.pqc.systems.shor.shor_distribution` compute the exact
outcome distribution classically with one FFT per value of :math:`a^x`,
which takes time exponential in the qubit count, so :math:`N` stays below 64
and the register at 14 qubits; no circuit or noise is modelled.

*References:* P. W. Shor, "Algorithms for quantum computation: discrete
logarithms and factoring", *Proceedings of the 35th Annual Symposium on
Foundations of Computer Science*, 124–134 (1994).
`DOI <https://doi.org/10.1109/SFCS.1994.365700>`__. Journal version: *SIAM J.
Comput.* 26(5), 1484–1509 (1997).
`DOI <https://doi.org/10.1137/S0097539795293172>`__.

.. minigallery:: ../../examples/pqc/quantum/plot_02_shor_period_finding.py

1996 -- Grover's search
-----------------------

Lov Grover found a quantum algorithm that finds one of :math:`M` marked
items among :math:`N` with about :math:`\sqrt{N/M}` oracle calls instead of
:math:`N/M`. Start from the uniform superposition and repeat two
reflections: the oracle flips the sign of the marked items, and the
diffusion operator reflects every amplitude about the mean. Together they
rotate the state by :math:`2\theta` towards the marked items:

.. math::

   \Pr[\text{success after } k] = \sin^2\bigl((2k + 1)\theta\bigr),
   \qquad \sin \theta = \sqrt{M / N}, \qquad
   k^\ast \approx \frac{\pi}{4} \sqrt{N / M}.

Bennett, Bernstein, Brassard and Vazirani proved the square root optimal. A
:math:`b`-bit key search, or a preimage search on a `hash
<https://cpoli.github.io/blockchainkit/history/crypto_breakthroughs.html#sha-256-as-a-standardized-hash-primitive>`__,
therefore keeps :math:`b/2` bits of security, which is why symmetric
cryptography only doubles its key sizes against quantum attackers.

*Implementation:* :func:`cybersecuritykit.pqc.systems.grover.grover_search`
simulates the real-amplitude state vector for up to :math:`2^{16}` items and
records the success probability after every iteration;
:func:`cybersecuritykit.pqc.systems.grover.grover_iterations` gives the
optimal count. The oracle is a list of marked indices, not a circuit.

*References:* L. K. Grover, "A fast quantum mechanical algorithm for
database search", *Proceedings of the 28th Annual ACM Symposium on Theory of
Computing*, 212–219 (1996).
`DOI <https://doi.org/10.1145/237814.237866>`__. C. H. Bennett, E. Bernstein,
G. Brassard and U. Vazirani, "Strengths and weaknesses of quantum
computing", *SIAM J. Comput.* 26(5), 1510–1523 (1997).
`DOI <https://doi.org/10.1137/S0097539796300933>`__.

.. minigallery:: ../../examples/pqc/quantum/plot_03_grover_search.py

1996 -- Ajtai's worst-case to average-case lattices
---------------------------------------------------

Cryptography needs problems that are hard on random instances, while
complexity theory usually proves hardness only for the worst case. Miklós
Ajtai closed that gap for lattices. He showed that finding a short nonzero
solution of a random linear system modulo :math:`q`, the short integer
solution (SIS) problem, is as hard as approximating short vectors in every
lattice of dimension :math:`n`. The problem gives a hash function at once:

.. math::

   f_A(x) = A x \bmod q, \qquad A \in \mathbb{Z}_q^{n \times m}, \quad
   x \in \{0, 1\}^m, \qquad f_A(x) = f_A(y) \Rightarrow A (x - y) \equiv 0.

For :math:`m > n \log_2 q` the hash compresses, so collisions exist, and
every collision is a vector with entries in :math:`\{-1, 0, 1\}` in the
lattice :math:`\Lambda^\perp(A)`. This was the first cryptographic
primitive with a worst-case security proof, and SIS is the problem under
Dilithium's signatures.

*Implementation:* :func:`cybersecuritykit.pqc.systems.ajtai.ajtai_keygen`,
:func:`cybersecuritykit.pqc.systems.ajtai.ajtai_hash` and
:func:`cybersecuritykit.pqc.systems.ajtai.ajtai_collision` use matrices
small enough (:math:`n = 2`, :math:`m = 8`) that a brute-force search finds
a collision in a few dozen inputs; the worst-case reduction itself is not
modelled.

*References:* M. Ajtai, "Generating hard instances of lattice problems",
*Proceedings of the 28th Annual ACM Symposium on Theory of Computing*,
99–108 (1996). `DOI <https://doi.org/10.1145/237814.237838>`__.

.. minigallery:: ../../examples/pqc/lattices/plot_04_ajtai_sis.py

1998 -- NTRU
------------

Jeffrey Hoffstein, Jill Pipher and Joseph Silverman designed a public-key
system in the ring :math:`\mathbb{Z}[x]/(x^N - 1)` whose operations cost
:math:`O(N^2)` instead of RSA's cubic exponentiations. The private key is a
small polynomial :math:`f`, invertible modulo :math:`p` and :math:`q`, and
the public key hides a second small polynomial :math:`g`:

.. math::

   h = f_q\, g \bmod q, \qquad e = p\, r h + m \bmod q, \qquad
   f e \equiv p\, r g + f m \pmod q.

The right-hand side is small, so as long as no coefficient leaves
:math:`(-q/2, q/2)` the decryptor recovers :math:`f m` exactly and strips
:math:`f` with :math:`f_p`; a wrapped coefficient is a decryption failure.
Coppersmith and Shamir noticed that :math:`(f, g)` is an unusually short
vector in a :math:`2N`-dimensional lattice built from :math:`h`, so NTRU's
security rests on lattice reduction failing at large :math:`N`. NTRU was
the first practical lattice cryptosystem and a NIST round-three finalist.

*Implementation:* :func:`cybersecuritykit.pqc.systems.ntru.ntru_keygen`,
:func:`cybersecuritykit.pqc.systems.ntru.ntru_encrypt` and
:func:`cybersecuritykit.pqc.systems.ntru.ntru_decrypt` use toy degrees
around :math:`N = 11` with ternary messages and no padding scheme;
:func:`cybersecuritykit.pqc.systems.ntru.ntru_lattice_attack` runs exact
LLL on the 14-dimensional lattice for :math:`N = 7` and rebuilds a working
key pair with :func:`cybersecuritykit.pqc.systems.ntru.ntru_keypair`.

*References:* J. Hoffstein, J. Pipher and J. H. Silverman, "NTRU: a
ring-based public key cryptosystem", *Algorithmic Number Theory
(ANTS-III)*, LNCS 1423, 267–288 (1998).
`DOI <https://doi.org/10.1007/BFb0054868>`__.

.. minigallery:: ../../examples/pqc/lattices/plot_05_ntru.py

1999 -- Unbalanced oil and vinegar
----------------------------------

Patarin answered his own attack with a trapdoor that needs no extension
field. In his oil-and-vinegar scheme of 1997, no central polynomial
multiplies two *oil* variables:

.. math::

   f_k(x) = \sum_{i \in V,\, j \in V \cup O} \alpha^{(k)}_{ij} x_i x_j
   + \sum_i \beta^{(k)}_i x_i + \gamma_k .

Fixing the *vinegar* variables at random makes every :math:`f_k` linear in
the oils, so the signer solves a linear system. The public key
:math:`P = F \circ S` hides the split behind a secret change of variables.
Aviad Kipnis and Adi Shamir broke the balanced case, with as many vinegars as
oils, in 1998: the oil space is an invariant subspace of
:math:`M_i^{-1} M_j` for the public quadratic forms. Kipnis, Patarin and
Louis Goubin repaired it the next year by taking more vinegars than oils.
UOV is still unbroken and is in NIST's additional signature round.

*Implementation:* :func:`cybersecuritykit.pqc.systems.oil_vinegar.uov_keygen`,
:func:`cybersecuritykit.pqc.systems.oil_vinegar.oil_vinegar_sign` and
:func:`cybersecuritykit.pqc.systems.oil_vinegar.oil_vinegar_verify` work over
a small prime field such as :math:`\mathrm{GF}(7)` with a few oils. The
message digest is SHAKE-256 reduced modulo :math:`q`, which is slightly
biased, and the Kipnis-Shamir attack is described but not implemented.

*References:* A. Kipnis, J. Patarin and L. Goubin, "Unbalanced Oil and Vinegar
signature schemes", *EUROCRYPT '99*, LNCS 1592, 206–222 (1999).
`DOI <https://doi.org/10.1007/3-540-48910-X_15>`__. A. Kipnis and A. Shamir,
"Cryptanalysis of the oil and vinegar signature scheme", *CRYPTO '98*, LNCS
1462, 257–266 (1998). `DOI <https://doi.org/10.1007/BFb0055733>`__.

.. minigallery:: ../../examples/pqc/multivariate/plot_34_oil_and_vinegar.py

2005 -- Regev's learning with errors
------------------------------------

Oded Regev asked for a secret :math:`s \in \mathbb{Z}_q^n` given many noisy
inner products with random vectors. Without the noise, Gaussian elimination
solves it; with small noise, Regev proved it as hard, for a quantum
algorithm, as approximating short vectors in every lattice. The samples
make a public key, and a bit is encrypted by summing a random subset
:math:`S` of them:

.. math::

   b_i = \langle a_i, s \rangle + e_i, \qquad
   u = \sum_{i \in S} a_i, \qquad
   v = \sum_{i \in S} b_i + \Bigl\lfloor \frac{q}{2} \Bigr\rfloor \cdot \mathrm{bit}.

Decryption computes :math:`v - \langle u, s \rangle`, the bit times
:math:`\lfloor q/2 \rfloor` plus the summed errors, and rounds; it is correct
while the summed errors stay below :math:`q/4`. Learning with errors became
the most flexible hardness assumption in cryptography, under encryption,
key exchange and fully homomorphic encryption alike.

*Implementation:* :func:`cybersecuritykit.pqc.systems.lwe.lwe_keygen`,
:func:`cybersecuritykit.pqc.systems.lwe.lwe_encrypt` and
:func:`cybersecuritykit.pqc.systems.lwe.lwe_decrypt` draw errors from
Kyber's centered binomial distribution instead of a discrete Gaussian, with
dimensions around 8; :func:`cybersecuritykit.pqc.systems.lwe.lwe_gaussian_attack`
shows elimination recovering the secret only when the noise is zero.

*References:* O. Regev, "On lattices, learning with errors, random linear
codes, and cryptography", *Proceedings of the 37th Annual ACM Symposium on
Theory of Computing*, 84–93 (2005).
`DOI <https://doi.org/10.1145/1060590.1060603>`__. Journal version: *J. ACM*
56(6), 34 (2009). `DOI <https://doi.org/10.1145/1568318.1568324>`__.

.. minigallery:: ../../examples/pqc/lwe/plot_06_regev_lwe.py

2009 -- Fiat-Shamir with aborts
-------------------------------

The `Fiat-Shamir heuristic
<https://cpoli.github.io/blockchainkit/history/crypto_breakthroughs.html#the-fiat-shamir-heuristic-from-interaction-to-signatures>`__
turns an identification protocol into a signature by hashing the
commitment into the challenge. Over lattices it leaks: the response
:math:`z = y + c s` is the mask shifted by the secret, so averaging many
signatures reveals :math:`s`. Vadim Lyubashevsky's fix is rejection
sampling. The signer aborts and starts again unless :math:`z` lies in a box
that every possible :math:`c s` can reach:

.. math::

   w = a y_1 + y_2, \quad c = H(w, \mu), \quad z = y + c s, \quad
   \text{output } z \text{ only if } \|z\|_\infty \le B - \kappa.

Accepted responses are then exactly uniform on the box, whatever the
secret, at the cost of a few attempts per signature. His 2012 paper
"Lattice signatures without trapdoors" gave the ring form, which led to
CRYSTALS-Dilithium, standardized as ML-DSA in FIPS 204 (2024).

*Implementation:* :func:`cybersecuritykit.pqc.systems.aborts.lyubashevsky_keygen`,
:func:`cybersecuritykit.pqc.systems.aborts.lyubashevsky_sign` and
:func:`cybersecuritykit.pqc.systems.aborts.lyubashevsky_verify` follow the
2012 ring scheme with one ring element instead of Dilithium's module, no
rounding or hints, and a challenge derived from SHAKE-256;
:func:`cybersecuritykit.pqc.systems.aborts.lyubashevsky_leakage` averages
signatures to show the secret leaking when aborts are switched off.

*References:* V. Lyubashevsky, "Fiat-Shamir with aborts: applications to
lattice and factoring-based signatures", *ASIACRYPT 2009*, LNCS 5912,
598–616 (2009). `DOI <https://doi.org/10.1007/978-3-642-10366-7_35>`__.
V. Lyubashevsky, "Lattice signatures without trapdoors", *EUROCRYPT 2012*,
LNCS 7237, 738–755 (2012).
`DOI <https://doi.org/10.1007/978-3-642-29011-4_43>`__.

.. minigallery:: ../../examples/pqc/lattice_signatures/plot_08_fiat_shamir_aborts.py

2010 -- Ring learning with errors
---------------------------------

Regev's public key is an :math:`m \times n` matrix, quadratic in the
dimension. Vadim Lyubashevsky, Chris Peikert and Oded Regev replaced the
matrix by multiplication with one polynomial in
:math:`R_q = \mathbb{Z}_q[x]/(x^n + 1)`, :math:`n` a power of two, and
proved the ring problem as hard as worst-case problems on ideal lattices.
Keys shrink to :math:`n` numbers, products cost :math:`O(n \log n)` with the
number-theoretic transform, and one ciphertext carries :math:`n` bits:

.. math::

   b = a s + e, \qquad u = a r + e_1, \qquad
   v = b r + e_2 + \Bigl\lfloor \frac{q}{2} \Bigr\rceil m, \qquad
   v - u s = e r - e_1 s + e_2 + \Bigl\lfloor \frac{q}{2} \Bigr\rceil m.

The modulus :math:`x^n + 1` makes multiplication negacyclic: the
coefficient that wraps past :math:`x^{n-1}` comes back negated. Kyber,
Dilithium and most lattice schemes in use today work over this ring or a
module over it.

*Implementation:* :func:`cybersecuritykit.pqc.systems.ring_lwe.ring_lwe_keygen`,
:func:`cybersecuritykit.pqc.systems.ring_lwe.ring_lwe_encrypt` and
:func:`cybersecuritykit.pqc.systems.ring_lwe.ring_lwe_decrypt` implement
the paper's encryption with schoolbook multiplication instead of the NTT and
degrees around 16.

*References:* V. Lyubashevsky, C. Peikert and O. Regev, "On ideal lattices
and learning with errors over rings", *EUROCRYPT 2010*, LNCS 6110, 1–23
(2010). `DOI <https://doi.org/10.1007/978-3-642-13190-5_1>`__.

.. minigallery:: ../../examples/pqc/lwe/plot_07_ring_lwe.py

2011 -- XMSS and stateful Merkle signatures
-------------------------------------------

A one-time key is no use for a server that signs every day. Merkle's answer,
taught in `blockchainkit's Merkle tree entry
<https://cpoli.github.io/blockchainkit/history/structures_breakthroughs.html#merkle-trees-and-compact-authentication>`__,
hashes :math:`2^h` one-time public keys into a binary tree and publishes only
the root. This entry goes beyond the Lamport and Merkle entries there. Johannes
Buchmann, Erik Dahmen and Andreas Hülsing's XMSS uses Winternitz keys as the
leaves and needs only a second-preimage-resistant hash. A signature carries
the leaf index :math:`i`, the one-time signature, and the :math:`h` sibling
hashes that lead to the root:

.. math::

   v_0 = \operatorname{leaf}_i, \qquad
   v_{\ell+1} = H\bigl(v_\ell \,\|\, \operatorname{sibling}_\ell\bigr)
   \text{ (in left-right order)}, \qquad v_h \overset{?}{=} \text{root}.

The scheme is *stateful*: the signer must keep the index of the next unused
leaf and never sign twice with one leaf. A key restored from a backup or a
virtual-machine snapshot, or copied to two servers, signs again from an old
index, and the reused Winternitz leaf can then be forged like any reused
one-time key. RFC 8391 (2018) standardized XMSS, and NIST SP 800-208 (2020)
allows it only where the state can be managed in hardware.

*Implementation:* :func:`cybersecuritykit.pqc.systems.xmss.xmss_keygen`,
:func:`cybersecuritykit.pqc.systems.xmss.xmss_sign` and
:func:`cybersecuritykit.pqc.systems.xmss.xmss_verify` build trees of height at
most 10 with Winternitz leaves; signing returns a new key with the next index
instead of updating storage, and
:func:`cybersecuritykit.pqc.systems.xmss.xmss_forge` attacks signatures made
from a rolled-back key. The bitmasks and L-trees of the full scheme are
replaced by keyed hashing of the concatenated chain ends.

*References:* J. Buchmann, E. Dahmen and A. Hülsing, "XMSS -- a practical
forward secure signature scheme based on minimal security assumptions",
*Post-Quantum Cryptography (PQCrypto 2011)*, LNCS 7071, 117–129 (2011).
`DOI <https://doi.org/10.1007/978-3-642-25405-5_8>`__. A. Hülsing, D. Butin,
S. Gazdag, J. Rijneveld and A. Mohaisen, "XMSS: eXtended Merkle Signature
Scheme", RFC 8391 (2018). `DOI <https://doi.org/10.17487/RFC8391>`__.

.. minigallery:: ../../examples/pqc/hash_signatures/plot_61_xmss_merkle_signatures.py

2015 -- SPHINCS and stateless hash-based signatures
---------------------------------------------------

SPHINCS, by Daniel J. Bernstein and eight co-authors, removes the state that
makes XMSS fragile. This entry goes beyond blockchainkit's Lamport entry. A
secret randomizer and the message choose one of :math:`2^{dh}` leaves of a
*hypertree* of :math:`d` layers of XMSS-style trees of height :math:`h`; each
tree signs the root of the one below, and the bottom leaf holds a HORST
*few-time* key. HORST (after Reyzin and Reyzin's HORS, 2002) splits a message
hash into :math:`k` indices of :math:`a` bits and reveals those :math:`k` of
its :math:`t = 2^a` secrets, each with a Merkle path to the HORST root. With
:math:`2^{60}` leaves picked at random a key is rarely used twice, and HORST
survives a few reuses. After :math:`r` signatures with one HORST key, a forger
needs every index of a new message to be already revealed:

.. math::

   \Pr[\text{forgery}] = \bigl(1 - (1 - 2^{-a})^{rk}\bigr)^{k}.

The price is size: a SPHINCS-256 signature is about 41 kB, against about
2.5 kB for XMSS. Its descendant SPHINCS+ became SLH-DSA, standardized in FIPS
205 (2024).

*Implementation:* :func:`cybersecuritykit.pqc.systems.sphincs.sphincs_sign`
and :func:`cybersecuritykit.pqc.systems.sphincs.sphincs_verify` use at most 4
layers and HORST keys of at most :math:`2^{12}` secrets, against 12 layers,
total height 60 and :math:`2^{16}` secrets in SPHINCS-256;
:func:`cybersecuritykit.pqc.systems.sphincs.few_time_security` evaluates the
formula above and :func:`cybersecuritykit.pqc.systems.sphincs.horst_forge`
forges against an over-used HORST key. The ChaCha-based hash and the
HORST tree-top truncation of the real scheme are left out.

*References:* D. J. Bernstein, D. Hopwood, A. Hülsing, T. Lange, R.
Niederhagen, L. Papachristodoulou, M. Schneider, P. Schwabe and Z.
Wilcox-O'Hearn, "SPHINCS: practical stateless hash-based signatures",
*Advances in Cryptology -- EUROCRYPT 2015*, LNCS 9056, 368–397 (2015).
`DOI <https://doi.org/10.1007/978-3-662-46800-5_15>`__. L. Reyzin and N.
Reyzin, "Better than BiBa: short one-time signatures with fast signing and
verifying", *ACISP 2002*, LNCS 2384, 144–153 (2002).
`DOI <https://doi.org/10.1007/3-540-45450-0_11>`__.

.. minigallery:: ../../examples/pqc/hash_signatures/plot_62_sphincs_stateless.py

2018 -- CRYSTALS-Kyber (FIPS 203, 2024)
---------------------------------------

Kyber works with module learning with errors: a :math:`k \times k` matrix of
polynomials in :math:`\mathbb{Z}_{3329}[x]/(x^{256} + 1)`, between plain and
ring LWE, so one ring serves every security level. Keys and ciphertexts are
compressed by dropping low bits. The Fujisaki-Okamoto transform turns the
passively secure encryption into a key-encapsulation mechanism secure
against chosen ciphertexts:

.. math::

   (K, r) = G\bigl(m \,\|\, H(\mathrm{ek})\bigr), \qquad
   c = \mathrm{Enc}(\mathrm{ek}, m; r), \qquad
   \mathrm{Decaps}(c) = \begin{cases} K & \mathrm{Enc}(\mathrm{ek}, m'; r') = c \\
   J(z \,\|\, c) & \text{otherwise.} \end{cases}

The decapsulator re-encrypts what it decrypted and, on any mismatch,
returns a pseudorandom key from a secret :math:`z` instead of an error
(implicit rejection), so a tampered ciphertext gives the attacker nothing to
learn from. NIST selected Kyber in 2022 and published it as ML-KEM in FIPS
203 (2024).

*Implementation:* :func:`cybersecuritykit.pqc.systems.kyber.kyber_keygen`,
:func:`cybersecuritykit.pqc.systems.kyber.kyber_encapsulate` and
:func:`cybersecuritykit.pqc.systems.kyber.kyber_decapsulate` follow FIPS
203's structure and hash functions (SHA3-512, SHA3-256, SHAKE-128 and
SHAKE-256 from :mod:`hashlib`) with :math:`q = 3329`, but default to degree
16, multiply schoolbook instead of in the NTT domain and serialize
differently, so outputs are not FIPS 203 known answers.

*References:* J. Bos, L. Ducas, E. Kiltz, T. Lepoint, V. Lyubashevsky, J. M.
Schanck, P. Schwabe, G. Seiler and D. Stehlé, "CRYSTALS -- Kyber: a
CCA-secure module-lattice-based KEM", *IEEE European Symposium on Security
and Privacy (EuroS&P 2018)*, 353–367 (2018).
`DOI <https://doi.org/10.1109/EuroSP.2018.00032>`__. NIST, *FIPS 203:
Module-Lattice-Based Key-Encapsulation Mechanism Standard* (2024).
`DOI <https://doi.org/10.6028/NIST.FIPS.203>`__.

.. minigallery:: ../../examples/pqc/lwe/plot_09_kyber_kem.py

2022 -- Beullens breaks Rainbow
-------------------------------

Jintai Ding and Dieter Schmidt's Rainbow (2005) stacks oil-and-vinegar
layers: the oils of one layer are vinegars of the next, and an output map
:math:`T` mixes the layers. It reached the NIST final round. Ward Beullens
used the polar form

.. math::

   D(x, y) = P(x + y) - P(x) - P(y) + P(0).

For every :math:`x`, :math:`D_x = D(x, \cdot)` maps the last layer's oil space
:math:`O_2` into a fixed space :math:`W` of dimension :math:`o_2`. For a random
:math:`x`, :math:`\ker D_x` meets :math:`O_2` with probability about
:math:`1/q`. A vector :math:`y` there satisfies :math:`P_h(y) = 0` and
:math:`\operatorname{rank} D_y \le o_2`, a small system that Beullens solved
with a Gröbner basis. One such :math:`y` gives :math:`W = \operatorname{image}
D_y`, and then all of :math:`O_2` by linear algebra. The SL1 parameters fell
in about 53 hours on a laptop. It was the year two NIST candidates fell: SIKE
was broken months later by Castryck and Decru.

*Implementation:* :func:`cybersecuritykit.pqc.systems.oil_vinegar.rainbow_keygen`
builds a two-layer key over a small prime field, and
:func:`cybersecuritykit.pqc.systems.oil_vinegar.beullens_rainbow_attack`
recovers :math:`O_2` from the public key. The toy enumerates
:math:`\ker D_x` instead of solving the system with a Gröbner basis, and it
implements the simple attack, not the rectangular MinRank attack.

*References:* W. Beullens, "Breaking Rainbow takes a weekend on a laptop",
*CRYPTO 2022*, LNCS 13508, 464–479 (2022).
`DOI <https://doi.org/10.1007/978-3-031-15979-4_16>`__. J. Ding and D. Schmidt,
"Rainbow, a new multivariable polynomial signature scheme", *ACNS 2005*, LNCS
3531, 164–175 (2005). `DOI <https://doi.org/10.1007/11496137_12>`__.
W. Castryck and T. Decru, "An efficient key recovery attack on SIDH",
*EUROCRYPT 2023*, LNCS 14008, 423–447 (2023).
`DOI <https://doi.org/10.1007/978-3-031-30589-4_15>`__.

.. minigallery:: ../../examples/pqc/multivariate/plot_35_beullens_rainbow.py
