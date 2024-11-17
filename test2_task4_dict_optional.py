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

    hashes = [('63328352350c9bd9611497d97fef965bda1d94ca15cc47d5053e164f4066f546828eee451cb5edd6f2bba1ea0a82278d0aa76c7003c79082d3a31b8c9bc1f58b',
    'dbc3ab99'),
    ('86ed9024514f1e475378f395556d4d1c2bdb681617157e1d4c7d18fb1b992d0921684263d03dc4506783649ea49bc3c9c7acf020939f1b0daf44adbea6072be6',
    'fa46510a'),
    ('16ac21a470fb5164b69fc9e4c5482e447f04f67227102107ff778ed76577b560f62a586a159ce826780e7749eadd083876b89de3506a95f51521774fff91497e',
    '9e8dc114'),
    ('13ef55f6fdfc540bdedcfafb41d9fe5038a6c52736e5b421ea6caf47ba03025e8d4f83573147bc06f769f8aeba0abd0053ca2348ee2924ffa769e393afb7f8b5',
    'c202aebb'),
    ('9602a9e9531bfb9e386c1565ee733a312bda7fd52b8acd0e51e2a0a13cce0f43551dfb3fe2fc5464d436491a832a23136c48f80b3ea00b7bfb29fedad86fc37a',
    'd831c568'),
    ('799ed233b218c9073e8aa57f3dad50fbf2156b77436f9dd341615e128bb2cb31f2d4c0f7f8367d7cdeacc7f6e46bd53be9f7773204127e14020854d2a63c6c18',
    '86d01e25'),
    ('7586ee7271f8ac620af8c00b60f2f4175529ce355d8f51b270128e8ad868b78af852a50174218a03135b5fc319c20fcdc38aa96cd10c6e974f909433c3e559aa',
    'a3582e40'),
    ('8522d4954fae2a9ad9155025ebc6f2ccd97e540942379fd8f291f1a022e5fa683acd19cb8cde9bd891763a2837a4ceffc5e89d1a99b5c45ea458a60cb7510a73',
    '6f966981'),
    ('6f5ad32136a430850add25317336847005e72a7cfe4e90ce9d86b89d87196ff6566322d11c13675906883c8072a66ebe87226e2bc834ea523adbbc88d2463ab3',
    '894c88a4'),
    ('21a60bdd58abc97b1c3084ea8c89aeaef97d682c543ff6edd540040af20b5db228fbce66fac962bdb2b2492f40dd977a944f1c25bc8243a4061dfeeb02ab721e',
    '4c8f1a45')
    ]


    cracked_passwords = salted_dictionary_cracking(hashes, 'PasswordDictionary.txt')

    print("Cracked passwords:")
    for i, password in enumerate(cracked_passwords):
        print(f"{i+1}) Hash: {password}")

    # This section is calculating the average execution time and peak memory usage
    print("Calculating average execution time, please wait...")
    timer = timeit.timeit(lambda: salted_dictionary_cracking(hashes, 'PasswordDictionary.txt'), number=100)
    print(f"Average execution time (Dictionary Attack) over 100 runs: {timer / 100:.5f} seconds")
    print("Calculating peak memory usage, please wait...")
    mem_usage = memory_usage((salted_dictionary_cracking, (hashes, 'PasswordDictionary.txt')))
    print(f"Peak memory usage (Dictionary Attack): {max(mem_usage):.2f} MiB")