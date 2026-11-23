Exercises: cybersecuritykit.classical
=====================================

Each problem comes from the exercise at the end of a gallery example. Try it
in the example's notebook first, then open the solution. Every solution is
run by the documentation build, so its code is known to work.

1. Frequency analysis: how short is too short?
----------------------------------------------

From :doc:`/api/gallery/classical/frequency_analysis/plot_01_al_kindi`.
Shorten the passage. At what length does the minimum of the :math:`\chi^2`
scores stop landing on 17?

.. dropdown:: Solution

   .. doctest::

      >>> ciphertext = csk.classical.shift_encrypt("The harbour master kept the lamp", 17)
      >>> [csk.classical.break_shift_cipher(ciphertext[:n]).shift for n in range(1, 11)]
      [6, 6, 17, 17, 17, 17, 10, 17, 17, 17]

   One or two letters are matched to whichever shift makes them common
   English letters, and at seven letters (THEHARB) the rare B tips the score
   to another shift. From eight letters on the true shift wins every time.
   The test is statistical: it needs enough letters for the counts to look
   like English, and a short passage with unusual letters can fool it.

2. Alberti's disk: the period of a turning disk
-----------------------------------------------

From :doc:`/api/gallery/classical/polyalphabetic/plot_01_alberti_disk`. With
``period=1`` show that letters 26 places apart are encrypted the same way, and
explain how that helps an attacker.

.. dropdown:: Solution

   .. doctest::

      >>> disk = "QWERTYUIOPASDFGHJKLZXCVBNM"
      >>> ciphertext = csk.classical.alberti_encrypt("E" * 30, disk, period=1)
      >>> ciphertext
      'TYUIOPASDFGHJKLZXCVBNMQWERTYUI'
      >>> ciphertext[:4] == ciphertext[26:]
      True

   After 26 turns the inner ring is back where it started, so the cipher is a
   keyword cipher with a period of 26. Taking every 26th letter gives a
   simple substitution, which frequency analysis breaks once the message is
   long enough. Alberti avoided this by turning the disk at irregular,
   secret points.

3. Keyword ciphers: when a longer key is not longer
---------------------------------------------------

From :doc:`/api/gallery/classical/polyalphabetic/plot_02_vigenere`. Encrypt
with ``"LEMONLEMON"`` and with ``"L"``. Which is really a longer key, and which
is a shift cipher?

.. dropdown:: Solution

   .. doctest::

      >>> text = "attack at dawn"
      >>> csk.classical.vigenere_encrypt(text, "LEMONLEMON") == csk.classical.vigenere_encrypt(text, "LEMON")
      True
      >>> csk.classical.vigenere_encrypt(text, "L") == csk.classical.shift_encrypt(text, 11)
      True

   A repeated keyword has the period of its shortest repeating unit, so
   ``"LEMONLEMON"`` is the same cipher as ``"LEMON"``. A one-letter keyword
   uses one alphabet: it is the shift cipher with shift 11. The strength of
   the cipher is its true period, not the length of the word written down.

4. Playfair: reversed pairs
---------------------------

From :doc:`/api/gallery/classical/digraphic/plot_01_playfair`. Encrypt
``"AB"`` and ``"BA"`` under the example key, and explain how an attacker can
use the result.

.. dropdown:: Solution

   .. doctest::

      >>> csk.classical.playfair_encrypt("AB", "playfair example")
      'PD'
      >>> csk.classical.playfair_encrypt("BA", "playfair example")
      'DP'

   All three Playfair rules act on the two cells symmetrically, so reversing
   a plaintext pair reverses its ciphertext. English has common reversed
   pairs (ER and RE, ES and SE, ON and NO); a ciphertext pair and its reverse
   that are both frequent are good guesses for one of them, and each guess
   fixes cells of the square.

5. Hill: blocks that cannot reveal the key
------------------------------------------

From :doc:`/api/gallery/classical/digraphic/plot_02_hill`. Which pairs of
2-letter plaintext blocks cannot be used to recover a :math:`2 \times 2` key?
Find one with determinant divisible by 13.

.. dropdown:: Solution

   .. doctest::

      >>> key = [[3, 3], [2, 5]]
      >>> ciphertext = csk.classical.hill_encrypt("BBAN", key)
      >>> csk.classical.hill_known_plaintext("BBAN", ciphertext, 2)
      Traceback (most recent call last):
      ...
      ValueError: no choice of n plaintext blocks gives an invertible matrix

   The blocks BB and AN are the columns :math:`(1, 1)` and :math:`(0, 13)`,
   with determinant :math:`13`. Solving :math:`K = C P^{-1}` needs
   :math:`P^{-1}` modulo 26, which exists only when the determinant shares no
   factor with 26. Any pair whose determinant is even or a multiple of 13
   leaves the key ambiguous; an attacker then needs more plaintext.

6. The two-time pad: why the bytes are small
--------------------------------------------

From :doc:`/api/gallery/classical/stream/plot_01_two_time_pad`. Explain why
two upper-case ASCII texts XOR to values below 32, and why a space XORs a
letter into its lower-case form.

.. dropdown:: Solution

   .. doctest::

      >>> ord("A") ^ ord("Z")
      27
      >>> chr(ord("A") ^ ord(" "))
      'a'

   Upper-case letters are 65 to 90, which in binary all start ``010``; XOR
   cancels those top bits and leaves a number below 32. A space is 32, the
   single bit that separates upper and lower case in ASCII, so a letter XORed
   with a space flips case. A lower-case letter in the combined stream
   therefore marks a space in one of the two messages, which is where crib
   dragging starts.

7. Rejewski: the plugboard does not change cycle lengths
--------------------------------------------------------

From :doc:`/api/gallery/classical/enigma/plot_01_rejewski`. Prove that
conjugation, :math:`S P S^{-1}`, never changes cycle lengths, and check it on
the machine.

.. dropdown:: Solution

   .. doctest::

      >>> bare = csk.classical.rejewski_characteristic(csk.classical.EnigmaSettings(("III", "I", "II")), "KDO")
      >>> plugged = csk.classical.rejewski_characteristic(
      ...     csk.classical.EnigmaSettings(("III", "I", "II"), "B", "AB CD"), "KDO"
      ... )
      >>> bare == plugged
      True

   If :math:`P` has a cycle :math:`(a_1\,a_2 \dots a_k)`, then
   :math:`S P S^{-1}` sends :math:`S(a_i)` to :math:`S(a_{i+1})`, so it has
   the cycle :math:`(S(a_1)\,S(a_2) \dots S(a_k))` of the same length. The
   plugboard only relabels the letters in each cycle. That is why the Polish
   catalogue could ignore the plugboard's :math:`1.5 \times 10^{14}` settings.

8. The bombe: a shorter crib
----------------------------

From :doc:`/api/gallery/classical/enigma/plot_02_bombe`. Shorten the crib to
``"WETTER"`` and search again. How many stops does the bombe report?

.. dropdown:: Solution

   .. doctest::

      >>> settings = csk.classical.EnigmaSettings(("I", "II", "III"))
      >>> ciphertext = csk.classical.enigma_encrypt("WETTERVORHERSAGEBISKAYA", settings, "JXM")
      >>> csk.classical.crib_menu(ciphertext, "WETTER", 0).loops
      0
      >>> csk.classical.bombe_search(ciphertext, "WETTER", 0, settings).positions
      ('JXM',)

   Without a plugboard, six crib letters already fix the start: there are
   :math:`26^3 = 17{,}576` starts and :math:`26^6 \approx 3 \times 10^8`
   possible six-letter ciphertexts, so a wrong start matches by chance about
   once in 17,000 searches. The real bombe had to allow every plugboard
   setting as well, and only the menu's loops gave it a test that held for
   all of them at once; a six-letter crib with no loop would have stopped on
   almost every start.

9. Perfect secrecy needs as many keys as messages
-------------------------------------------------

From :doc:`/api/gallery/classical/information_theory/plot_01_perfect_secrecy`.
How many keys would perfect secrecy need for all 676 two-letter messages?

.. dropdown:: Solution

   .. doctest::

      >>> prior = {"HI": 0.5, "OK": 0.5}
      >>> csk.classical.shift_cipher_posterior(prior, csk.classical.shift_encrypt("HI", 3)).perfect
      False
      >>> csk.classical.one_time_pad_posterior(prior, "XQ").perfect
      True

   A shift key maps HI to only 26 of the 676 possible ciphertexts, so seeing
   the ciphertext rules most messages out. For every ciphertext to be
   consistent with every message, each message needs its own key to every
   ciphertext: at least 676 keys, one per two-letter pad. The 26-key shift
   cipher falls short by a factor of 26.

10. Unicity distance after compression
--------------------------------------

From :doc:`/api/gallery/classical/information_theory/plot_02_unicity_distance`.
Raise the entropy of the plaintext towards 4.7 bits per letter. What happens to
the unicity distance?

.. dropdown:: Solution

   .. doctest::

      >>> round(csk.classical.unicity_distance(26).distance, 2)
      1.47
      >>> round(csk.classical.unicity_distance(26, letter_entropy=4.0).distance, 2)
      6.71

   The distance is the key entropy divided by the redundancy, and compression
   removes redundancy. At 4.0 bits per letter a shift cipher already needs
   almost five times as much ciphertext; as the entropy approaches
   :math:`\log_2 26`, the redundancy goes to zero and the distance grows
   without bound. Every attack on this page exploits redundancy: letter
   counts, repeated fragments, English bigrams.
