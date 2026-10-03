import hashlib


def hash_file(path, algorithm="sha256"):
    """Return the hash of a file as a text string, e.g. 'e3b0c442...'."""
    hasher = hashlib.new(algorithm)   # create a hasher: "sha256", "sha1", "md5", ...

    with open(path, "rb") as f:       # "rb" = open the file as raw bytes
        while True:
            chunk = f.read(65536)     # read 64 KB at a time
            if not chunk:             # an empty chunk means we reached the end
                break
            hasher.update(chunk)      # feed this piece into the hasher

    return hasher.hexdigest()         # the finished fingerprint, as hex text


def verify_file(path, expected_hash, algorithm="sha256"):
    """Return True if the file's hash matches the expected hash, else False."""
    actual_hash = hash_file(path, algorithm)
    expected_hash = expected_hash.strip().lower()   # ignore spaces and capitals
    return actual_hash == expected_hash


# This block only runs when you start the file directly:
#     python3 hashing.py somefile.txt
# It does NOT run when another file imports hash_file().
if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python3 hashing.py <file>")
        sys.exit(1)

    print(hash_file(sys.argv[1]))
