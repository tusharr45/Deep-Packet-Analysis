blocked=[]

with open("rules.txt") as f:

    for line in f:

        blocked.append(line.strip().lower())


def check(domain):

    domain=domain.lower()

    for b in blocked:

        if b in domain:

            return True

    return False