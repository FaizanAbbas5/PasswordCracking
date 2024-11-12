import hashlib
import itertools

# Function to compute the SHA-512 hash of a password
def hash_password(password):
    """
    This function computes the SHA-512 hash of a given password using the built-in hashlib library
    returns a hexadecimal string for the password hash
    """
    return hashlib.sha512(password.encode('ascii')).hexdigest()

# Function to brute-force find passwords from hashes
def brute_force_crack(hashes):
    """
    This function uses brute-force to find passwords from hashes
    It takes the list of hashes as input
    returns the cracked passwords
    """
    # Possible characters in the password (as mentioned in the coursework document)
    characters = 'abcdefghijklmnopqrstuvwxyz0123456789'
    
    cracked_passwords = {}
    # the max password length is set here
    for length in range(1, 6):
        # using itertools.product, we generate all the possible combinations of the characters provided
        for text in itertools.product(characters, repeat=length):
            password = ''.join(text)

            # Here we hash the resulting password using the hash_password function defined above
            hashed_password = hash_password(password)
            
            # Here we check if the hash matches one of the provided hashes
            if hashed_password in hashes:
                cracked_passwords[hashed_password] = password
                
            # If all of the passwords are cracked, return the results
            if len(cracked_passwords) == len(hashes):
                return cracked_passwords
                
    return cracked_passwords


# List of hashes provided
hashes = ['f14aae6a0e050b74e4b7b9a5b2ef1a60ceccbbca39b132ae3e8bf88d3a946c6d8687f3266fd2b626419d8b67dcf1d8d7c0fe72d4919d9bd05efbd37070cfb41a',
'e85e639da67767984cebd6347092df661ed79e1ad21e402f8e7de01fdedb5b0f165cbb30a20948f1ba3f94fe33de5d5377e7f6c7bb47d017e6dab6a217d6cc24',
'4e2589ee5a155a86ac912a5d34755f0e3a7d1f595914373da638c20fecd7256ea1647069a2bb48ac421111a875d7f4294c7236292590302497f84f19e7227d80',
'afd66cdf7114eae7bd91da3ae49b73b866299ae545a44677d72e09692cdee3b79a022d8dcec99948359e5f8b01b161cd6cfc7bd966c5becf1dff6abd21634f4b']

# Here we call the brute_force_crack function and store the results in the cracked variable
cracked_passwords = brute_force_crack(hashes)

print("Cracked passwords:")
for hash, password in cracked_passwords.items():
    print(f"Hash: {hash}\nPassword: {password}")
