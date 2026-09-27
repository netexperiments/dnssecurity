import random

seed = 'tuvydgaattack.pt'
numberDomains = 500

def map_to_lowercase_letter(s):
    return ord('a') + ((s - ord('a')) % 26)

def next_domain(domain):
    dl = [ord(x) for x in list(domain)]
    dl[0] = map_to_lowercase_letter(dl[0] + dl[3])
    dl[1] = map_to_lowercase_letter(dl[0] + 2*dl[1])
    dl[2] = map_to_lowercase_letter(dl[0] + dl[2] - 1)
    dl[3] = map_to_lowercase_letter(dl[1] + dl[2] + dl[3])
    return ''.join([chr(x) for x in dl])

domain = seed
domain = next_domain(domain)

generated_domains = []
for i in range(numberDomains):
    generated_domains.append(domain)
    domain = next_domain(domain)

random_domain = random.choice(generated_domains)
print(random_domain)