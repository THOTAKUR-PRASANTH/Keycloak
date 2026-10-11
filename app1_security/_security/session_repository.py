# repositories/pkce_repository.py

class PKCERepository:
    _store = {}

    @classmethod
    def save(cls, state: str, verifier: str):

        cls._store[state] = {
            "code_verifier": verifier
        }

    @classmethod
    def get(cls, state: str):

        return cls._store.get(state)

    @classmethod
    def remove(cls, state: str):

        cls._store.pop(state, None)