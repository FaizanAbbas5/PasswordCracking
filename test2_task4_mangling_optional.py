import hashlib
import timeit
from memory_profiler import memory_usage    # To use memory_profiler please refer to the additional instructions document

def mangling_rules(word):
    """This function defines the various mangling rules to be used"""
    # Apply various mangling techniques
    variations = [word]
    variations.append(word.capitalize())            # Capitalize first letter
    variations.append(word.replace('a', '@'))       # replace 'a' with '@'
    variations.append(word.replace('o', '0'))       # replace 'o' with '0'
    variations.append(word + "123")                 # Add '123' at the end of the word
    
    return variations

def dictionary_attack_with_mangling(hashes, dictionary_file):
    """This function is used to perform the password cracking"""
    with open(dictionary_file, 'r') as file:
        dictionary = [password.strip() for password in file]

    cracked_passwords = []
    for salted_hash, salt in hashes:
        found = False
        for word in dictionary:
            # Call the mangling_rules function to generate all the defined variations of the word
            mangled_words = mangling_rules(word)
            for mangled_word in mangled_words:
                # add salt to the base password before hashing it
                salted_word = mangled_word + salt
                hashed = hashlib.sha512(salted_word.encode('ascii')).hexdigest()

                # compare the hash with the target hash
                if hashed == salted_hash:
                    cracked_passwords.append(mangled_word)
                    found = True
                    break
            if found:
                break

        if not found:
            cracked_passwords.append(None)

    return cracked_passwords

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


    cracked_passwords = dictionary_attack_with_mangling(hashes, 'PasswordDictionary.txt')

    print("Cracked passwords:")
    for i, password in enumerate(cracked_passwords):
        print(f"{i+1}) Hash: {password}")

    # This section is calculating the average execution time and peak memory usage
    print("Calculating average execution time, please wait...")
    timer = timeit.timeit(lambda: dictionary_attack_with_mangling(hashes, 'PasswordDictionary.txt'), number=100)
    print(f"Average execution time (Word mangling) over 100 runs: {timer / 100:.5f} seconds")
    print("Calculating peak memory usage, please wait...")
    mem_usage = memory_usage((dictionary_attack_with_mangling, (hashes, 'PasswordDictionary.txt')))
    print(f"Peak memory usage (Word mangling): {max(mem_usage):.2f} MiB")
