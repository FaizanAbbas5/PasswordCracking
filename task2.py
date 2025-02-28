import hashlib

# Function to compute the SHA-512 hash of a password
def hash_password(password):
    """
    This function computes the SHA-512 hash of a given password using the built-in hashlib library
    returns a hexadecimal string for the password hash
    """
    return hashlib.sha512(password.encode('ascii')).hexdigest()

# Function to perform dictionary cracking
def dictionary_cracking(hashes, dictionary):
    """
    This function uses dictionary attack to find passwords from hashes
    It takes the list of hashes and the password dictionary as input
    returns the cracked passwords
    """
    cracked_passwords = []
    cached_hashes = {}

    # here we read the contents of the file
    with open(dictionary, 'r') as file:
        passwords = file.readlines()

    # Loop through each hash and try to find a matching password
    for target_hash in hashes:
        found = False
        for password in passwords:
            password = password.strip()
            
            # Check if the password has already been hashed and cached
            if password in cached_hashes:
                hashed_password = cached_hashes[password]
            else:
                # If not, hash the password and store it in the cache
                hashed_password = hash_password(password)
                cached_hashes[password] = hashed_password

            # If the hash matches, append the password and break out of the loop
            if hashed_password == target_hash:
                cracked_passwords.append(password)
                found = True
                break  # Stop checking once the password is found for the current hash

        # If no matching password was found for this hash, append None
        if not found:
            cracked_passwords.append(None)

    return cracked_passwords



# List of hashes provided
hashes = ['31a3423d8f8d93b92baffd753608697ebb695e4fca4610ad7e08d3d0eb7f69d75cb16d61caf7cead0546b9be4e4346c56758e94fc5efe8b437c44ad460628c70',
'9381163828feb9072d232e02a1ee684a141fa9cddcf81c619e16f1dbbf6818c2edcc7ce2dc053eec3918f05d0946dd5386cbd50f790876449ae589c5b5f82762',
'a02f6423e725206b0ece283a6d59c85e71c4c5a9788351a24b1ebb18dcd8021ab854409130a3ac941fa35d1334672e36ed312a43462f4c91ca2822dd5762bd2b',
'834bd9315cb4711f052a5cc25641e947fc2b3ee94c89d90ed37da2d92b0ae0a33f8f7479c2a57a32feabdde1853e10c2573b673552d25b26943aefc3a0d05699',
'0ae72941b22a8733ca300161619ba9f8314ccf85f4bad1df0dc488fdd15d220b2dba3154dc8c78c577979abd514bf7949ddfece61d37614fbae7819710cae7ab',
'6768082bcb1ad00f831b4f0653c7e70d9cbc0f60df9f7d16a5f2da0886b3ce92b4cc458fbf03fea094e663cb397a76622de41305debbbb203dbcedff23a10d8a',
'0f17b11e84964b8df96c36e8aaa68bfa5655d3adf3bf7b4dc162a6aa0f7514f32903b3ceb53d223e74946052c233c466fc0f2cc18c8bf08aa5d0139f58157350',
'cf4f5338c0f2ccd3b7728d205bc52f0e2f607388ba361839bd6894c6fb8e267beb5b5bfe13b6e8cc5ab04c58b5619968615265141cc6a8a9cd5fd8cc48d837ec',
'1830a3dfe79e29d30441f8d736e2be7dbc3aa912f11abbffb91810efeef1f60426c31b6d666eadd83bbba2cc650d8f9a6393310b84e2ef02efa9fe161bf8f41d',
'3b46175f10fdb54c7941eca89cc813ddd8feb611ed3b331093a3948e3ab0c3b141ff6a7920f9a068ab0bf02d7ddaf2a52ef62d8fb3a6719cf25ec6f0061da791'
]

# Here we call the dictionary_cracking function and store the results in the cracked variable
cracked_passwords = dictionary_cracking(hashes, 'PasswordDictionary.txt')

print("Cracked passwords:")
for i, password in enumerate(cracked_passwords):
    print(f"{i+1}) Hash: {password}")