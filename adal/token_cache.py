class TokenCache(object):
    def __init__(self):
        self._entries = []

    def find(self, query):
        entries = []
        for e in self._entries:
            matched = True
            for key in query:
                if query[key] != e[key]:
                    matched = False
                    break
            if matched:
                entries.append(e)

        return entries

    def remove(self, entries):
        matches = self.find(entries)
        return [x for x in self._entries if x not in matches]

    def add(self, entries):
        self.remove(entries)
        self._entries.extend(entries)
