Program Environment: Ubuntu 14.04 LTS

## Finding the Encryption Key

* Encryption Algorithm: DES-AES (combination of DES and AES)
	* plaintext *m* is first encrypted with a 64 bits key *k1* using **DES** in ECB mode
	* then, is encrypted again with a 128 bits key *k2* using **AES-128** in CBC mode
	* all zeros for the initialization vector (16 null characters)
* This program implements a key-recovery attack on the DES-AES algorithm
	* input: plaintext-ciphertext pair *(m,c)*
	* output: *k1*, *k2*
* MD5 hash values of passwords: https://seclab.skku.edu/wp-content/uploads/2017/09/ passwords.txt
	* *k1*: the first 64 bits of the MD5 hash value generated from a password *p1*
	* *k2*: the MD5 hash value itself generated from a password *p2*

### Input and Output Files
* Input file: ***PlaintextCiphertext.txt***
```
SKKU is the top university in the world
CBMsz223gfHe6AH6I+IIEjpXxjFlupBrGYZ8CDYYr9WJj4j0cMuL8uAA/Yxr9pNK
```
* Output file: ***keys.txt***
```
coders
piewtf
```

## Methodology
* **Meet in the middle**
	* Encrypt (DES) the plaintext with all possible given passwords.
	* Decrypt (AES-128) the ciphertext with every possible decrypt key.
		* Cross check if there exist a match in the encrypted list with the decrypted result
* DES encryption
	* In this program, I have only taken the first 8 bytes of the plain text to encrypt.
	* ```struct keyOutput```
		* Stores values of the key, output, and password used
		* A total of 184389 structures are made (made for every password)
	* The encrypted results are sorted so that binary search is possible
* AES decryption
	* In this program, I have only taken the first 24 bytes of the cipher text to decrypt.
		* The cipher text is encoded in Base64, so it is decoded into 18 bytes
		* Take the first 16 bytes of the decoded 18 bytes to decrypt
* Since the decrypted result is of 16 bytes and the encrypted result is of 8 bytes, only the first 8 bytes of the decrypted result is used for comparison.

## Command Line Arguments

This program uses the DES and AES libraries of Openssl

```
$ gcc DES_AES.c -lcrypto
$ ./a.out
```
