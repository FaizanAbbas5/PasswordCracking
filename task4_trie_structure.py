import hashlib
import timeit
from memory_profiler import memory_usage    # To use memory_profiler please refer to the additional instructions document

# Trie Node class to represent each node in the Trie
class TrieNode:
    """This class represents each Node in the Trie"""
    def __init__(self):
        self.children = {} # each node has a dictionary, children, to store susequent characters
        self.is_end_of_word = False # This is a flag used to indicate when a word is formed


class Trie:
    """This class is used to hold all the dictionary words"""
    def __init__(self):
        self.root = TrieNode() # The root is an empty string

    def insert(self, word):
        """This method is used to insert a word to the Trie"""
        node = self.root
        for char in word:
            if char not in node.children:
                node.children[char] = TrieNode()
            node = node.children[char]
        node.is_end_of_word = True

# Function to compute the SHA-512 hash of a password
def hash_password(password):
    """
    This function computes the SHA-512 hash of a given password using the built-in hashlib library
    returns a hexadecimal string for the password hash
    """
    return hashlib.sha512(password.encode('ascii')).hexdigest()

# Build the Trie from the dictionary file
def build_trie(dictionary_file):
    """This function is used to build the Trie structure.
        It reads the content of the dictionary.
    """
    trie = Trie()
    with open(dictionary_file, 'r') as file:
        for password in file:
            password = password.strip()
            trie.insert(password) # Here we call the insert method to insert the password into the Trie
    return trie


def trie_crack_hashes(hashes, trie):
    """This function is used to search the Trie.
        It also performs the password cracking
    """
    cracked_passwords = []

    for hash, salt in hashes:
        found = False
        stack = [(trie.root, "")]  # stack for iterative DFS

        while stack:
            current_node, prefix = stack.pop()

            if current_node.is_end_of_word:
                salted_password = prefix + salt # We add salt to the password
                hashed_password = hash_password(salted_password) # Hashing is performed using the method defined above
                if hashed_password == hash:
                    cracked_passwords.append(prefix)
                    found = True
                    break

            for char, child_node in current_node.children.items():
                stack.append((child_node, prefix + char))

        if not found:
            cracked_passwords.append(None)  # Incase the password is not found

    return cracked_passwords

if __name__ == "__main__":

    hashes = [
        ('8d7e27707f5666723555230ae151a3a3deca6a0b5ecacb339e0c00b4e5cfb620e8675288acf886e4555eead17132d9ab7f834422bc678cf167858b6aff829df8',
    'dbc3ab99'),
    ('7da010084bef37683b398bbdcd3aae7603cdf67001775bd19bfe781c0d11ad909250b6a2c3f9ce042d0b9719e30c9676002ac2c8b1fd2d039358f2f40fa8621f',
    'fa46510a'),
    ('82f3bfdfd147ba4b6cb498e0ae2bdd6d63fd0ae208479722eeafcdb66da0bfe477666acaac8e8f121ee065fe8201041ca718281176fa82a653a7a8ab79eb3f12',
    '9e8dc114'),
    ('171253f4db20d31253fe776ebab2faec819d59ad0e86af8de2a0c543badfbea7159205b9aa72d948d801b2f5f3cc3264a03839ee6b502dd0439d03cd7fc62534',
    'c202aebb'),
    ('9602a9e9531bfb9e386c1565ee733a312bda7fd52b8acd0e51e2a0a13cce0f43551dfb3fe2fc5464d436491a832a23136c48f80b3ea00b7bfb29fedad86fc37a',
    'd831c568'),
    ('0b812b65c36db455dbf36f3c7efa9ee17907a1492eb031f2aebb3b487ba26426954cf2bb553f2ac09cb275f53a5dff3dc1aef9680a00c655d7162b8754fabe30',
    '86d01e25'),
    ('b63f4263b35a1b8e714fc2745c067de4e9e28b243a097b6d689cecfeae326228426756fecde2ce049233aee9397b0d1f38e1b4bba8771568f5575d42a99662b4',
    'a3582e40'),
    ('2c624983b0d6b5d20613aed523138b44baf06e6f0b9eae8aeb97f6a24dc6df4dd42f55c931b5a312c6f04c03eba7e36483a983cfc56b0d1bdea45990c593fbb9',
    '6f966981'),
    ('d366a5f17cbea31f14da39dd25ec14e0994ad163abd14edb92efe64f8aa8d9b2184d5ee68885f5f0ae509b662053592b59f8db634078236b3a0bcfb8dbaf86d7',
    '894c88a4'),
    ('264d795b8a66ebe3a96487e26520d8306c17cba5fd74581fa3d314d674234f38b50713349f8353a8e7e8ee9b3c4147612786affadf54f96b0be1c6066c26798f',
    '4c8f1a45'),
    ]

    # Build the Trie from the dictionary file
    trie = build_trie('NewPasswordDictionary.txt')

    cracked_passwords = trie_crack_hashes(hashes, trie)

    print("Cracked passwords:")
    for i, password in enumerate(cracked_passwords):
        print(f"{i+1}) Hash: {password}")

    # This section is calculating the average execution time and peak memory usage
    print("Calculating average execution time, please wait...")
    timer = timeit.timeit(lambda: trie_crack_hashes(hashes, build_trie('NewPasswordDictionary.txt')), number=100)
    print(f"Average execution time (Trie structure) over 100 runs: {timer / 100:.5f} seconds")
    print("Calculating peak memory usage, please wait...")
    mem_usage = memory_usage((trie_crack_hashes, (hashes, build_trie('NewPasswordDictionary.txt'))))
    print(f"Peak memory usage (Trie structure): {max(mem_usage):.2f} MiB")