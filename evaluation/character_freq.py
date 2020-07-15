# This file calculate the character frequency for each domain the majestic_million dataset.

import tldextract
from collections import Counter

domains = []
counter = 0
f = open("majestic_million.txt", "r")
for domain in f:
    # if counter > 0:
    #     break
    ext = tldextract.extract("http://www." + domain.rstrip())
    domains.append(Counter(ext.domain))
    # counter += 1

letter_freq = sum(domains, Counter())

print(letter_freq)
sum_letters = sum(letter_freq.values())
print(sum_letters)

print(len(letter_freq.keys()))

a = {k: v / total for total in (sum(letter_freq.values()),) for k, v in letter_freq.items()}

print(a)