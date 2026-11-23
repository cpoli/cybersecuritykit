"""English language statistics used to score candidate plaintexts.

Letter frequencies are the widely reprinted table of Lewand,
*Cryptological Mathematics* (MAA, 2000), in percent. Bigram scores come from
counting the short original corpus below, with add-one smoothing: enough to
rank candidate decryptions, which is all the solvers need.
"""

import math
from functools import cache

from cybersecuritykit.constants import ALPHABET

ENGLISH_FREQUENCIES: dict[str, float] = {
    "A": 8.167, "B": 1.492, "C": 2.782, "D": 4.253, "E": 12.702, "F": 2.228, "G": 2.015,
    "H": 6.094, "I": 6.966, "J": 0.153, "K": 0.772, "L": 4.025, "M": 2.406, "N": 6.749,
    "O": 7.507, "P": 1.929, "Q": 0.095, "R": 5.987, "S": 6.327, "T": 9.056, "U": 2.758,
    "V": 0.978, "W": 2.360, "X": 0.150, "Y": 1.974, "Z": 0.074,
}  # fmt: skip

CORPUS = """
The harbour was quiet in the early morning when the fishing boats came back with
their nets full of silver fish. The old men who sat by the wall watched them come
in and talked about the weather and the price of bread and the news from the city.
Nobody in the village had ever been far from the sea, and most of them had no wish
to go. They knew the names of the rocks and the currents and the birds, and they
could tell from the colour of the sky whether there would be a storm before night.
A young woman named Clara kept the small shop at the corner of the market square.
She sold rope and lamps and paint, and in the winter she sold coal to the families
who lived on the hill. Every evening she wrote the accounts in a thick green book,
and every Sunday she walked along the cliffs to the lighthouse where her brother
worked as the keeper. He was a patient man who liked numbers and puzzles, and he
spent the long hours of the night writing letters to friends in distant countries.
One autumn a stranger arrived on the last boat of the season. He carried a leather
case and a heavy coat, and he asked at the inn for a room that looked over the water.
He said that he was studying the movement of the tides, but he spent most of his
time walking through the streets and listening to the people talk. The children
followed him from house to house, because he gave them sweets and told them stories
about mountains covered in snow and rivers so wide that you could not see the other
side. After a few weeks the village grew used to him, and the old men invited him
to sit with them by the wall. He asked them many questions about the lighthouse and
the ships that passed in the night, and he wrote down their answers in a small book.
When the first winter storm came, the stranger went out to the cliffs and watched
the waves break against the rocks. Clara saw him there and thought that he looked
worried. That night the lamp in the lighthouse went dark for almost an hour, and a
ship that was passing far out at sea turned away from the coast. In the morning the
stranger was gone, and his room at the inn was empty except for a page of strange
letters that nobody could read. Clara took the page to her brother, who studied it
for many days. He counted how often each letter appeared and compared the result
with the letters of ordinary writing. Slowly the pattern began to show itself, and
one evening he understood that the message described the hours when the light was
kept and the times when the keeper changed his watch. He told the harbour master,
and the next spring a new lock was fitted to the door of the lighthouse. The story
was told in the village for many years, and the children who had followed the
stranger grew up and told it to their own children by the fire in the evening.
"""
"""str: Original English prose from which the bigram statistics are counted."""


@cache
def bigram_log_probabilities() -> tuple[tuple[float, ...], ...]:
    """Return ``table[a][b] = log P(b | a)`` for letter indices, add-one smoothed."""
    letters = [ALPHABET.index(c) for c in CORPUS.upper() if c in ALPHABET]
    counts = [[1] * 26 for _ in range(26)]
    for a, b in zip(letters, letters[1:], strict=False):
        counts[a][b] += 1
    return tuple(tuple(math.log(c / sum(row)) for c in row) for row in counts)
