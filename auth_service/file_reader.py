def reader(path, op, strip):
    with open(path, op) as r:
        if strip:
            return r.read().strip()
        return r.read()
