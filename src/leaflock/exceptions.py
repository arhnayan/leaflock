class LeaflockError(Exception):
    pass


class DecryptionError(LeaflockError):
    pass


class InvalidPassphraseError(DecryptionError):
    pass


class WrongMachineError(DecryptionError):
    pass


class CorruptedFileError(LeaflockError):
    pass


class InvalidKeyfileError(LeaflockError):
    pass
