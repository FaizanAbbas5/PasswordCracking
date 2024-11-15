import hashlib
import timeit
from memory_profiler import memory_usage # To use memory_profiler please refer to the additional instructions document

# Function to compute the SHA-512 hash of a password
def hash_password(password):
    """
    This function computes the SHA-512 hash of a given password using the built-in hashlib library
    returns a hexadecimal string for the password hash
    """
    return hashlib.sha512(password.encode('ascii')).hexdigest()

# Function to perform dictionary cracking
def salted_dictionary_cracking(hashes, passwords):
    """
    This function uses dictionary attack to find passwords from (salted) hashes
    It takes the list of salted hashes (along with the salt) and the password dictionary as input
    returns the cracked passwords
    """
    cracked_passwords = []
    
    with open(passwords, 'r') as file:
        passwords = file.readlines()
    
    # Cache to store already computed password + salt hashes
    cached_hashes = {}

    # For each hash, try to find the matching password
    for hash, salt in hashes:
        found = False  # Flag to stop early if a match is found
        
        for password in passwords:

            password = password.strip()
            # Check if the (password, salt) pair is already hashed and cached
            if (password, salt) in cached_hashes:
                hashed_password = cached_hashes[(password, salt)]
            else:
                # If not, hash the password + salt and store it in the cache
                salted_password = password + salt
                hashed_password = hash_password(salted_password)
                cached_hashes[(password, salt)] = hashed_password
            
            # If the hash matches, append the password and break out of the loop
            if hashed_password == hash:
                cracked_passwords.append(password)
                found = True
                break  # Stop checking once the password is found for the current hash

        if not found:
            cracked_passwords.append(None)
    
    return cracked_passwords

# mmeory profiler requires the use of if __name__ == "__main__" clause
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


    cracked_passwords = salted_dictionary_cracking(hashes, 'NewPasswordDictionary.txt')

    print("Cracked passwords:")
    for i, password in enumerate(cracked_passwords):
        print(f"{i+1}) Hash: {password}")

    # This section is calculating the average execution time and peak memory usage
    print("Calculating average execution time, please wait...")
    timer = timeit.timeit(lambda: salted_dictionary_cracking(hashes, 'NewPasswordDictionary.txt'), number=100)
    print(f"Average execution time (Dictionary Attack) over 100 runs: {timer / 100:.5f} seconds")
    print("Calculating peak memory usage, please wait...")
    mem_usage = memory_usage((salted_dictionary_cracking, (hashes, 'NewPasswordDictionary.txt')))
    print(f"Peak memory usage (Dictionary Attack): {max(mem_usage):.2f} MiB")