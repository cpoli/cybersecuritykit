Exercises: cybersecuritykit.pqc
===============================

Each problem comes from the exercise at the end of a gallery example. Try it
in the example's notebook first, then open the solution. Every solution is
run by the documentation build, so its code is known to work. The problems
follow the order of :doc:`the history page </history/pqc_breakthroughs>`.

1. Prange: the cost of guessing an information set
--------------------------------------------------

From :doc:`/api/gallery/pqc/codes/plot_30_prange_isd`. Show that the
expected work grows like :math:`(n / (n - k))^t` for small :math:`t`, and
estimate how many guesses a code with :math:`n = 1024`, :math:`k = 524` and
:math:`t = 50` (McEliece's 1978 parameters) needs.

.. dropdown:: Solution

   .. doctest::

      >>> import math
      >>> p = csk.pqc.prange_success_probability(1024, 524, 50)
      >>> round(math.log2(1 / p), 1)
      53.6
      >>> round(50 * math.log2(1024 / 500), 1)
      51.7

   With :math:`r = n - k`, the probability is
   :math:`\binom{n - t}{r - t} / \binom{n}{r} = \prod_{i=0}^{t-1} (r - i)/(n - i)`.
   Each factor is close to :math:`r/n` when :math:`t` is small, so
   :math:`p \approx (r/n)^t` and the expected number of guesses is about
   :math:`(n / (n - k))^t`. For McEliece's parameters that estimate gives
   :math:`2^{51.7}` and the exact product :math:`2^{53.6}`, because the
   factors shrink as :math:`i` grows. Each guess costs a Gaussian elimination,
   so plain Prange needs roughly :math:`2^{80}` bit operations; Stern's and
   later decoders lower that, and McEliece's parameters were retired only
   because computers caught up.

2. McEliece: the size of the public key
---------------------------------------

From :doc:`/api/gallery/pqc/codes/plot_31_mceliece`. The public key has
:math:`k \times n` bits. Compute its size for the Classic McEliece parameters
:math:`n = 3488, k = 2720`, and explain why the systematic form
:math:`(I_k \mid A)` lets you store only :math:`A`.

.. dropdown:: Solution

   .. doctest::

      >>> n, k = 3488, 2720
      >>> k * n // 8
      1185920
      >>> k * (n - k) // 8
      261120

   The full generator matrix takes about 1.19 MB. Gaussian elimination brings
   any generator of the same code to the form :math:`(I_k \mid A)` with
   :math:`A` of size :math:`k \times (n - k)`, and the identity block is
   known to everyone, so only :math:`A` is published: 261,120 bytes, the
   public-key size of the ``mceliece348864`` parameter set. The systematic
   form copies the message into the first :math:`k` bits of the codeword,
   which is why it is used with Niederreiter's syndrome form or with a
   transform that randomizes the message.

3. Winternitz: why the checksum stops a forger
----------------------------------------------

From :doc:`/api/gallery/pqc/hash_signatures/plot_60_winternitz_signatures`.
With one observed signature the forger fails. Explain how the checksum stops
it, and why two signatures with different digits can be enough.

.. dropdown:: Solution

   .. doctest::

      >>> key = csk.pqc.winternitz_keygen(11, n=8)
      >>> seen = [(m, csk.pqc.winternitz_sign(key, m)) for m in (b"a", b"b", b"c", b"d")]
      >>> csk.pqc.winternitz_forge(key.public, seen[:1], max_tries=1000).message is None
      True
      >>> forgery = csk.pqc.winternitz_forge(key.public, seen)
      >>> forgery.message, forgery.tested
      (b'forgery 434', 435)
      >>> csk.pqc.winternitz_verify(key.public, forgery.message, forgery.signature)
      True

   From one signature the forger can only hash forward, which raises digits.
   A message whose digits are all at least as large as the signed ones has a
   checksum :math:`C = \sum (w - 1 - d_i)` that is smaller, and a smaller
   checksum digit would need a value *earlier* on its chain, which means
   inverting the hash. Every message therefore has some digit, message or
   checksum, below the revealed one. With several signatures the forger knows,
   on each chain, the lowest value revealed by any of them, so a message wins
   as soon as each of its digits, checksum included, is at least that minimum.
   Four signatures here make such a message easy to find.

4. LLL: the price of a stronger Lovász condition
------------------------------------------------

From :doc:`/api/gallery/pqc/lattices/plot_01_lll_reduction`. Reduce the same
scrambled basis with ``delta=0.5`` and ``delta=0.99``. Compare the swap
counts and explain why a larger :math:`\delta` costs more swaps.

.. dropdown:: Solution

   .. doctest::

      >>> import random
      >>> rng = random.Random(3)
      >>> basis = [[int(i == j) for j in range(4)] for i in range(4)]
      >>> for _ in range(12):
      ...     i, j = rng.sample(range(4), 2)
      ...     factor = rng.choice([-3, -2, 2, 3])
      ...     basis[i] = [x + factor * y for x, y in zip(basis[i], basis[j])]
      >>> loose = csk.pqc.lll_reduce(basis, delta=0.5)
      >>> tight = csk.pqc.lll_reduce(basis, delta=0.99)
      >>> loose.swaps, tight.swaps
      (8, 10)
      >>> sorted(sum(x * x for x in row) for row in loose.basis)
      [1, 1, 1, 2]
      >>> sorted(sum(x * x for x in row) for row in tight.basis)
      [1, 1, 1, 1]

   The algorithm swaps two vectors whenever
   :math:`\|b_i^*\|^2 < (\delta - \mu_{i,i-1}^2)\|b_{i-1}^*\|^2`. A larger
   :math:`\delta` makes that condition fire more often, so more swaps happen
   before the basis is accepted. With :math:`\delta = 0.5` the algorithm stops
   early and leaves a vector of squared length 2; with :math:`\delta = 0.99`
   it recovers the four unit vectors. Each swap shrinks a potential by at
   least a factor :math:`\delta`, so the bound on the number of swaps grows
   like :math:`1/\log(1/\delta)` as :math:`\delta \to 1`, which is why
   :math:`\delta = 1` itself is excluded.

5. Niederreiter: how much a syndrome can carry
----------------------------------------------

From :doc:`/api/gallery/pqc/codes/plot_32_niederreiter`. Count the messages
a Niederreiter ciphertext can carry, :math:`\log_2 \binom{n}{t}` bits, for
:math:`n = 32, t = 3` and for :math:`n = 3488, t = 64`, and compare with the
ciphertext length.

.. dropdown:: Solution

   .. doctest::

      >>> import math
      >>> math.comb(32, 3), round(math.log2(math.comb(32, 3)), 1)
      (4960, 12.3)
      >>> round(math.log2(math.comb(3488, 64)), 1)
      456.3

   The toy carries 12.3 bits in a 15-bit syndrome, and the Classic McEliece
   parameters carry 456 bits in :math:`n - k = 768` bits. The ciphertext is
   longer than the message because not every syndrome is the syndrome of a
   weight-:math:`t` error: the decodable ones are a small fraction. Even so,
   a Niederreiter ciphertext is far shorter than a McEliece one, which has
   :math:`n` bits.

6. Patarin: the bilinear relation
---------------------------------

From :doc:`/api/gallery/pqc/multivariate/plot_33_matsumoto_imai_patarin`.
Derive :math:`X^{2^{2\theta}} Y = X Y^{2^\theta}` from
:math:`Y = X^{2^\theta + 1}`, and explain why the Frobenius powers make it
bilinear over :math:`\mathrm{GF}(2)`. How many unknown coefficients does it
have for :math:`n = 5`?

.. dropdown:: Solution

   .. doctest::

      >>> keys = csk.pqc.matsumoto_imai_keygen(5, 2, seed=2026)
      >>> plaintext = (1, 0, 1, 1, 0)
      >>> result = csk.pqc.patarin_linearization(
      ...     keys.public, keys.public.evaluate(plaintext), seed=1
      ... )
      >>> (5 + 1) ** 2, result.plaintext == plaintext
      (36, True)

   Raise :math:`Y = X^{2^\theta + 1}` to the power :math:`2^\theta`:
   :math:`Y^{2^\theta} = X^{2^{2\theta} + 2^\theta}`. Multiplying by
   :math:`X` gives :math:`X Y^{2^\theta} = X^{2^{2\theta}} X^{2^\theta + 1}
   = X^{2^{2\theta}} Y`. Squaring is linear over :math:`\mathrm{GF}(2)`
   because :math:`(a + b)^2 = a^2 + b^2` in characteristic 2, so
   :math:`X^{2^{2\theta}}` and :math:`Y^{2^\theta}` are linear in the bits of
   :math:`X` and :math:`Y`. Each side is a product of something linear in
   :math:`X` and something linear in :math:`Y`: bilinear. The secret affine
   maps keep the degree, so the relations between plaintext :math:`u` and
   ciphertext :math:`v` have :math:`n^2` coefficients
   :math:`\gamma_{ij}`, :math:`n` each of :math:`\alpha_i` and
   :math:`\beta_j`, and one :math:`\delta`: :math:`(n + 1)^2 = 36` unknowns
   for :math:`n = 5`, found from a few dozen pairs.

7. Shor: when the period is not enough
--------------------------------------

From :doc:`/api/gallery/pqc/quantum/plot_02_shor_period_finding`. Run
``shor_factor(15, base=14)``: it finds period 2 but returns no factors.
Explain why from :math:`14 \equiv -1 \pmod{15}`, and count the bases modulo
15 for which the classical post-processing succeeds.

.. dropdown:: Solution

   .. doctest::

      >>> import math
      >>> result = csk.pqc.shor_factor(15, base=14, seed=1)
      >>> result.period, result.factors
      (2, None)
      >>> [a for a in range(2, 15) if math.gcd(a, 15) == 1
      ...  and csk.pqc.shor_factor(15, base=a, seed=1).factors]
      [2, 4, 7, 8, 11, 13]

   The period is even, but :math:`14^{r/2} = 14 \equiv -1`, so
   :math:`\gcd(14 - 1, 15) = 1` and :math:`\gcd(14 + 1, 15) = 15` are the
   trivial divisors. Of the eight bases coprime to 15, the base 1 has odd
   period 1 and the base 14 has :math:`a^{r/2} \equiv -1`; the other six
   succeed. For a product of two odd primes at least half the bases work, so
   a few random tries suffice.

8. Grover: overshooting the target
----------------------------------

From :doc:`/api/gallery/pqc/quantum/plot_03_grover_search`. Run
``grover_search(8, [42], iterations=24)``. Explain from the rotation picture
why running too long lowers the success probability again.

.. dropdown:: Solution

   .. doctest::

      >>> best = csk.pqc.grover_search(8, [42], seed=1)
      >>> best.iterations, round(best.success[-1], 5)
      (12, 0.99995)
      >>> round(csk.pqc.grover_search(8, [42], iterations=24, seed=1).success[-1], 4)
      0.0059

   The state stays in the plane spanned by the marked state and the uniform
   superposition of the others. It starts at angle :math:`\theta` from the
   unmarked direction, with :math:`\sin\theta = 1/16` for :math:`N = 256`,
   and each iteration rotates it by :math:`2\theta`, so the success
   probability after :math:`k` iterations is :math:`\sin^2((2k + 1)\theta)`.
   Twelve iterations bring the angle to :math:`25\theta \approx \pi/2`.
   Twenty-four bring it to :math:`49\theta \approx 3.06`, close to
   :math:`\pi`, where the state points away from the target again. The
   probability is periodic in :math:`k`, so the number of iterations has to
   be chosen, not run until success.

9. Ajtai: why the hash must compress
------------------------------------

From :doc:`/api/gallery/pqc/lattices/plot_04_ajtai_sis`.
``ajtai_keygen(2, 8, 31)`` raises an error. Compute :math:`n \log_2 q`,
explain why the key generator insists on compression, and find the smallest
:math:`m` it accepts for :math:`q = 31`.

.. dropdown:: Solution

   .. doctest::

      >>> import math
      >>> csk.pqc.ajtai_keygen(2, 8, 31)
      Traceback (most recent call last):
      ...
      ValueError: m must exceed n log2 q, or the hash does not compress
      >>> round(2 * math.log2(31), 2)
      9.91
      >>> key = csk.pqc.ajtai_keygen(2, 10, 31, seed=1)
      >>> csk.pqc.ajtai_collision(key).difference
      (1, 0, -1, 1, 0, -1, 0, 0, 0, 0)

   The hash maps :math:`2^m` inputs to :math:`q^n = 961` values. With
   :math:`m = 8` there are only 256 inputs, so the map can be injective and
   collisions need not exist. Ajtai's security argument is that a collision
   gives a short vector :math:`z \in \{-1, 0, 1\}^m` with :math:`Az = 0`, a
   SIS solution; that only makes sense when collisions are guaranteed, which
   the pigeonhole principle gives once :math:`2^m > q^n`, that is
   :math:`m > n \log_2 q \approx 9.91`. The smallest accepted :math:`m` is
   10, and a collision there is found after a short search.

10. NTRU: choosing q so decryption never fails
----------------------------------------------

From :doc:`/api/gallery/pqc/lattices/plot_05_ntru`. Bound the largest
coefficient of :math:`p r g + f m` for the parameters above, and find the
smallest :math:`q` for which failure is impossible.

.. dropdown:: Solution

   .. doctest::

      >>> import random
      >>> keys = csk.pqc.ntru_keygen(11, 3, 53, 3, seed=1)
      >>> sum(x != 0 for x in keys.f), sum(x != 0 for x in keys.g)
      (7, 6)
      >>> 3 * 6 + 7
      25
      >>> rng = random.Random(5)
      >>> messages = [tuple(rng.choice((-1, 0, 1)) for _ in range(11)) for _ in range(200)]
      >>> sum(
      ...     csk.pqc.ntru_decrypt(keys, csk.pqc.ntru_encrypt(keys.public, m, seed=s)) != m
      ...     for s, m in enumerate(messages)
      ... )
      0

   With :math:`N = 11` and :math:`d = 3`, the blinding polynomial :math:`r`
   and :math:`g` each have six nonzero coefficients :math:`\pm 1`, so a
   coefficient of :math:`r g` is a sum of at most six terms :math:`\pm 1`
   and :math:`|p\,r g| \le 18`. The key :math:`f` has seven nonzero
   coefficients and the message is ternary, so :math:`|f m| \le 7`. Every
   coefficient of :math:`p r g + f m` is at most 25 in absolute value, and
   the centered lift recovers it exactly when :math:`q > 50`. The smallest
   such modulus is 51; the toy key generator accepts only prime powers, so
   the smallest it accepts is 53, and no decryption fails there. Real NTRU
   chooses :math:`q` smaller than this worst case and accepts a tiny failure
   rate.

11. Oil and vinegar: the signer's linear system
-----------------------------------------------

From :doc:`/api/gallery/pqc/multivariate/plot_34_oil_and_vinegar`. Count the
equations and unknowns the signer solves once the vinegars are fixed, and
estimate how often that system is singular over :math:`\mathrm{GF}(q)` for
:math:`o = 3`.

.. dropdown:: Solution

   .. doctest::

      >>> import math
      >>> keys = csk.pqc.uov_keygen(7, vinegar=6, oil=3, seed=2026)
      >>> keys.public.n_vars, keys.public.n_polys
      (9, 3)
      >>> round(1 - math.prod(1 - 7**-i for i in range(1, 4)), 3)
      0.163

   There is one equation per polynomial and one unknown per oil variable:
   three equations in three unknowns. No term multiplies two oils, so once
   the six vinegars are fixed each equation is linear in the oils. A random
   :math:`o \times o` matrix over :math:`\mathrm{GF}(q)` is invertible with
   probability :math:`\prod_{i=1}^{o} (1 - q^{-i})`, so it is singular about
   16% of the time for :math:`q = 7`. The signer then draws new vinegars and
   tries again, which is why signing is randomized.

12. Regev: how much noise decryption tolerates
----------------------------------------------

From :doc:`/api/gallery/pqc/lwe/plot_06_regev_lwe`. A ciphertext sums about
:math:`m/2` errors. Estimate the largest :math:`\eta` for which that sum
stays below :math:`q/4` with high probability, and compare with the failure
curve.

.. dropdown:: Solution

   .. doctest::

      >>> round((97 / 4 / 3) ** 2 / 8, 1)
      8.2
      >>> def failure_rate(eta):
      ...     wrong = 0
      ...     for k in range(10):
      ...         keys = csk.pqc.lwe_keygen(8, 32, 97, eta=eta, seed=k)
      ...         wrong += sum(
      ...             csk.pqc.lwe_decrypt(keys, csk.pqc.lwe_encrypt(keys.public, s % 2, seed=s))
      ...             != s % 2
      ...             for s in range(40)
      ...         )
      ...     return wrong / 400
      >>> [failure_rate(eta) for eta in (4, 8, 24)]
      [0.0, 0.025, 0.21]

   A centered binomial error with parameter :math:`\eta` has variance
   :math:`\eta/2`, so the sum of :math:`m/2 = 16` errors has standard
   deviation :math:`\sqrt{8\eta}`. Decryption is correct while the sum stays
   below :math:`q/4 \approx 24`. Asking for three standard deviations gives
   :math:`\sqrt{8\eta} \le 8.1`, so :math:`\eta \lesssim 8`. The measured
   curve agrees: no failures at :math:`\eta = 4`, the first failures at
   :math:`\eta = 8`, a little more often than the three-sigma tail because
   the random subset sometimes sums more than 16 errors, and one ciphertext
   in five fails at :math:`\eta = 24`.

13. Fiat-Shamir with aborts: the expected number of attempts
------------------------------------------------------------

From :doc:`/api/gallery/pqc/lattice_signatures/plot_08_fiat_shamir_aborts`.
The expected number of attempts depends on how much of the box
:math:`[-B, B]` survives the cut at :math:`B - \kappa`. Derive it for one
coefficient, raise it to the number of coefficients, and compare with the
measured average.

.. dropdown:: Solution

   .. doctest::

      >>> keys = csk.pqc.lyubashevsky_keygen(16, seed=1)
      >>> keys.public.bound, keys.public.kappa
      (128, 4)
      >>> round((257 / 249) ** 32, 2)
      2.75
      >>> attempts = [csk.pqc.lyubashevsky_sign(keys, b"m", seed=s).attempts for s in range(200)]
      >>> sum(attempts) / 200
      2.69

   A coefficient of :math:`y` is uniform on the :math:`2B + 1 = 257` integers
   of :math:`[-B, B]`, and :math:`z = y + c s` shifts it by at most
   :math:`\kappa = 4`. Whatever the shift, exactly :math:`2(B - \kappa) + 1 =
   249` values of :math:`y` land in :math:`[-(B - \kappa), B - \kappa]`, so a
   coefficient survives with probability :math:`249/257`. The signature has
   :math:`2n = 32` coefficients in :math:`z_1` and :math:`z_2`, so an attempt
   survives with probability :math:`(249/257)^{32}`, and the number of
   attempts is geometric with mean :math:`(257/249)^{32} \approx 2.75`. The
   200 measured signatures average 2.69.

14. Ring-LWE: the negacyclic matrix
-----------------------------------

From :doc:`/api/gallery/pqc/lwe/plot_07_ring_lwe`. Write :math:`a` as an
:math:`n \times n` matrix whose product with the coefficient vector of
:math:`s` equals :math:`a s` in :math:`R_q`. Which entries carry a minus
sign, and why?

.. dropdown:: Solution

   .. doctest::

      >>> from cybersecuritykit.pqc.utils.rings import multiply
      >>> q, n = 257, 4
      >>> a, s = (5, 7, 11, 13), (1, 0, 2, 3)
      >>> matrix = [[a[i - j] if i >= j else -a[n + i - j] for j in range(n)] for i in range(n)]
      >>> matrix
      [[5, -13, -11, -7], [7, 5, -13, -11], [11, 7, 5, -13], [13, 11, 7, 5]]
      >>> tuple(sum(x * y for x, y in zip(row, s)) % q for row in matrix) == multiply(a, s, q, -1)
      True

   Column :math:`j` holds the coefficients of :math:`x^j a`. Multiplying by
   :math:`x` shifts the coefficients up by one, and the top coefficient
   wraps around to the constant term with a minus sign because
   :math:`x^n = -1` in :math:`R_q`. So entry :math:`(i, j)` is
   :math:`a_{i-j}` on and below the diagonal and :math:`-a_{n+i-j}` above it:
   the entries above the diagonal carry the minus sign. The matrix is
   fixed by its first column, :math:`n` numbers instead of the :math:`n^2`
   of plain LWE, which is the whole saving of the ring version.

15. XMSS: authentication paths and leaf reuse
---------------------------------------------

From :doc:`/api/gallery/pqc/hash_signatures/plot_61_xmss_merkle_signatures`.
How many hashes does a verifier compute for the authentication path of a
height-:math:`h` tree, and how many one-time keys does the key hold? Why does
the forger need several signatures on the *same* leaf rather than one
signature on each of several leaves?

.. dropdown:: Solution

   .. doctest::

      >>> key = csk.pqc.xmss_keygen(1, height=3, n=8)
      >>> first = csk.pqc.xmss_sign(key, b"a")
      >>> len(first.signature.auth_path), first.key.next_index, 2**3
      (3, 1, 8)

   The verifier first recovers the leaf from the Winternitz signature, then
   hashes it with one sibling per level: :math:`h` node hashes for a tree of
   height :math:`h`, three here. The tree has :math:`2^h = 8` leaves, each a
   separate Winternitz key, so the key signs eight messages and its state
   moves to the next leaf after each one. Signatures on different leaves
   reveal chain values of different keys, and each key is still used once,
   which is safe. A forgery needs several signatures under one Winternitz
   key, as in the previous exercise, and that happens only when the state is
   reused, for example after restoring a backup of the key.

16. SPHINCS: few-time keys at full size
---------------------------------------

From :doc:`/api/gallery/pqc/hash_signatures/plot_62_sphincs_stateless`. Real
SPHINCS uses :math:`k = 32`, :math:`a = 16` and a hypertree of 12 layers and
total height 60, so :math:`2^{60}` leaves. Use ``few_time_security`` to
explain why a few-time key there can sign several times without harm.

.. dropdown:: Solution

   .. doctest::

      >>> [round(csk.pqc.few_time_security(32, 16, r), 1) for r in (1, 4, 16, 64)]
      [352.0, 288.0, 224.2, 160.7]

   Each signature reveals :math:`k = 32` of the :math:`2^{16}` secrets in
   each of the HORST trees, and a forger must find a message whose 32
   indices are all among the revealed ones. After 64 signatures under one
   key that still costs about :math:`2^{160}` hashes, far above the
   :math:`2^{128}` target. Leaves are chosen from the message hash among
   :math:`2^{60}`, so even after :math:`2^{50}` signatures a given leaf is
   used more than a handful of times with negligible probability. The few-time
   scheme absorbs the collisions that a stateless random choice produces,
   which is what removes the need for state.

17. Kyber: why decapsulation never reports failure
--------------------------------------------------

From :doc:`/api/gallery/pqc/lwe/plot_09_kyber_kem`. Suppose decapsulation
raised an error on a failed re-encryption check instead of returning a
pseudorandom key. Explain how an attacker who can submit ciphertexts could
use that signal.

.. dropdown:: Solution

   .. doctest::

      >>> keys = csk.pqc.kyber_keygen(2, 16, seed=1)
      >>> sent = csk.pqc.kyber_encapsulate(keys.public, seed=2)
      >>> v = list(sent.ciphertext.v)
      >>> v[0] = (v[0] + 1) % 16
      >>> forged = csk.pqc.KyberCiphertext(sent.ciphertext.u, tuple(v))
      >>> rejected = csk.pqc.kyber_decapsulate(keys, forged)
      >>> rejected == sent.shared_key, len(rejected)
      (False, 32)

   Decryption of a lattice ciphertext succeeds while its noise stays below a
   threshold, and that noise depends on the secret key. An attacker who
   perturbs a valid ciphertext by a chosen amount and learns whether
   decryption still gives the same message learns one inequality on the
   secret coefficients. A few thousand such queries pin the key down, as in
   the key-mismatch and plaintext-checking attacks on IND-CPA lattice
   schemes. Kyber's Fujisaki-Okamoto transform re-encrypts the decrypted
   message, and on a mismatch it returns a key derived from a secret and the
   ciphertext, "implicit rejection". The forged ciphertext above gets a
   32-byte key that looks like any other, so the attacker cannot tell a
   rejection from a success and the oracle disappears. An explicit error, or
   a timing difference, would bring it back.

18. Beullens: the polar form and the oil space
----------------------------------------------

From :doc:`/api/gallery/pqc/multivariate/plot_35_beullens_rainbow`. Show that
:math:`D(x, y)` is bilinear and that :math:`D(y, y) = 2 P_h(y)`. Then argue
why a random :math:`x` gives a kernel :math:`\ker D_x` that meets
:math:`O_2` with probability about :math:`1/q` in this toy.

.. dropdown:: Solution

   .. doctest::

      >>> q = 7
      >>> keys = csk.pqc.rainbow_keygen(q, 3, 2, 2, seed=2026)
      >>> P = keys.public
      >>> zero = (0,) * P.n_vars
      >>> def polar(x, y):
      ...     xy = tuple((a + b) % q for a, b in zip(x, y))
      ...     parts = zip(P.evaluate(xy), P.evaluate(x), P.evaluate(y), P.evaluate(zero))
      ...     return tuple((s - a - b + c) % q for s, a, b, c in parts)
      >>> y = (1, 2, 3, 4, 5, 6, 0)
      >>> minus = tuple(-v % q for v in y)
      >>> twice_quadratic = tuple(
      ...     (a + b - 2 * c) % q for a, b, c in zip(P.evaluate(y), P.evaluate(minus), P.evaluate(zero))
      ... )
      >>> polar(y, y) == twice_quadratic
      True
      >>> guesses = [csk.pqc.beullens_rainbow_attack(P, 2, seed=s).guesses for s in range(20)]
      >>> sum(guesses) / 20
      4.85

   Write :math:`P(x) = Q(x) + L(x) + c` with :math:`Q` homogeneous quadratic
   and :math:`L` linear. The constant cancels in
   :math:`P(x + y) - P(x) - P(y) + P(0)`, the linear part cancels because
   :math:`L(x + y) = L(x) + L(y)`, and :math:`Q(x + y) - Q(x) - Q(y)` is the
   bilinear form of :math:`Q`. So :math:`D` is bilinear, and
   :math:`D(y, y) = Q(2y) - 2Q(y) = 2Q(y) = 2P_h(y)`; the code checks it
   with :math:`2Q(y) = P(y) + P(-y) - 2P(0)`. The map :math:`D_x` sends
   :math:`O_2` into :math:`W`, both of dimension :math:`o_2 = 2`, so on
   :math:`O_2` it is a random :math:`2 \times 2` matrix over
   :math:`\mathrm{GF}(q)`. It is singular, and its kernel meets :math:`O_2`,
   with probability about :math:`1/q`, so the attack needs a handful of
   guesses on average, the same order as :math:`q = 7`.
