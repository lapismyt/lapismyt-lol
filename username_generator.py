import random

adjectives = [
    "awesome", "brave", "calm", "daring", "eager", "fierce", "gentle", "happy",
    "jolly", "kind", "lively", "mighty", "nice", "proud", "quiet", "strong", "unique"
]

nouns = [
    "bear", "tiger", "eagle", "lion", "fox", "wolf", "panda", "shark", "elephant",
    "falcon", "rabbit", "dolphin", "whale", "koala", "otter", "giraffe", "penguin"
]


def generate_username():
    adjective = random.choice(adjectives)
    noun = random.choice(nouns)
    number = random.randint(1, 999)
    return f"{adjective}_{noun}{number}"
