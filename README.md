# PHE (Partially homomorphic encryption)
This is a simple implementation to demonstrate 3 notable PHEs: El-Gamal, RSA and Paillier encryption.

## El-Gamal encryption
 El-Gamal encryption system is a widely-used homomorphic encryption (HE) in public-key
 cryptography, proposed by T. ElGamal in 1985. The advent
 of El-Gamal algorithm is based on the Diffie–Hellman key exchange, 
 while its security strength is relied on the hardness
 of solving discrete logarithms. 

 El-Gamal cryptosystem is known as a PHE, 
 which allows to operate only homomorphic multiplications on ciphertexts.
  ```shell
  python3 Elgamal.py
   ```
 This is a simple demonstration of how it works.
 
 ## Paillier encryption
 The encryption of Paillier (1999) is an additively homomorphic cryptosystem, 
which is based on the composite residuosity problem 
and gathers many good properties.
 ```shell
  python3 Paillier.py
   ```
This is a simple demonstration of Paillier homomorphic encryption.
Here we attempts to show the basic mathematical operations
that can be performed on both ciphertexts and plaintexts.

 ## RSA encryption
 RSA was first introduced by Rivest et al. in 1978. 
The security of the cryptosystem relies on the practical hardness of
factoring the product of two large prime numbers, called the factoring problem. 

In HE, RSA is the first PHE and commonly used in practice. Compared to other HE schemes such as Paillier and El-Gamal,
RSA is much easier. Here we demonstrate a simple program of RSA 
and its multiplicatively homomorphic properties.
```shell
  python3 RSA.py
   ```
