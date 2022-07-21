# El-Gamal encryption system is a widely-used homomorphic encryption (HE) in public-key
# cryptography, proposed by T. ElGamal in 1985. The advent
# of El-Gamal algorithm is based on the Diffie–Hellman key exchange, 
# while its security strength is relied on the hardness
# of solving discrete logarithms. 

# El-Gamal cryptosystem is known as a Partial Homomorphic Encryption (PHE), 
# which allows to operate only homomorphic multiplications on ciphertexts.
# This is a simple demonstration of how it works.

import math
import random
import time
import gmpy2
from Crypto.Util.number import *


# Generating a safe prime p with k bits
# We call a prime number p a safe prime if p = 2q + 1 where q is also prime.
def generateSafePrime(k):
    q = getPrime(k-1)
    p = 2*q + 1
    while not gmpy2.is_prime(p):
        q = getPrime(k-1)
        p = 2*q + 1
    return p

# Find a generator of a cyclic group (or a primitive root of group mod p) 
# g is a primitive root if all prime factors of φ(p) = p-1, called P[i] satisfy: 
# g^((p-1)/P[i]) (mod p) is not congruent to 1.
# Because p is a safe prime p = 2q + 1, prime factors of φ(p) are 2 and q.
def generate_g(p):   
	q = (p-1)//2
	for g in range(2, p-1):
		if (gmpy2.powmod(g,2,p) != 1 and gmpy2.powmod(g,q,p) != 1):
			break
	return g		
		
class PrivateKey():
    def __init__(self, p):
        self.a = random.randint(1,p-1)
    def display_value(self):
        return f'a = {self.a}'        
class PublicKey():
    def __init__(self,a,p):
       self.p = p
       self.g = generate_g(self.p)
       self.h = gmpy2.powmod(self.g,a,self.p)
    def display_value(self):
       return f'p = {self.p} \ng = {self.g} \nh = {self.h}'  

# Encrypting a plaintext m using public keys
def encryption(pub,m):
	k = random.randint(1,pub.p-1)
	x = gmpy2.powmod(pub.g,k,pub.p) 
	s = gmpy2.powmod(pub.h,k,pub.p) 
	c= gmpy2.mul(s,m) 
	return x,c

# Decrypting a ciphertext (x,sm) using secret keys
def decryption(priv, x,sm):
	s_ = gmpy2.powmod(x,priv.a,pub.p)
	s_ = gmpy2.invert(s_,pub.p)
	sms = gmpy2.f_mod(gmpy2.mul(sm,s_),pub.p)
	return sms 

# Homomorphic multiplication of 2 ciphertexts 
def multiplication(x1,sm1,x2,sm2, pub):
	x = gmpy2.f_mod(gmpy2.mul(x1,x2),pub.p)
	c= gmpy2.f_mod(gmpy2.mul(sm1,sm2),pub.p)	
	return x,c
	
print("\n*********************************************************")
print("\n*         El-Gamal cryptosystem demonstration           *")
print( "\n*********************************************************")
print("")

# The time to generate a safe prime depends on key size.
# So to have less time in key generation process, it's better to choose a small number, e.g. 10, 20, etc.
print('Please enter a El-Gamal key size in bits and hit enter:')
try:
	bits = int(input())
except ValueError:
	print("Please enter an integer, e.g. 10, 20, etc.")
	exit()

print( "\n\n*************** PART I: KEY GENERATION ******************")

start = time.time()
p = generateSafePrime(bits)
priv = PrivateKey(p)
pub = PublicKey(priv.a,p)
end = time.time()
print("key_size = ", bits)
print(priv.display_value())
print(pub.display_value())

print( "\n\n*********** PART II: HOMOMORPHIC OPERATIONS *************")
print("")
print('Please enter the first message (m1 < p) :')
try:
	m1 = int(input())
except ValueError:
	print("Please enter integer numbers.")
	exit()
print('Please enter the second message (m2 < p) :')
try:
	m2 = int(input())
except ValueError:
	print("Please enter integer numbers.")
	exit()		
print("m1 = ", m1, "\nm2 = ",m2)

#*****1. ENCRYPTION *****
start1=time.time()
x1,c1 = encryption(pub,m1)
x2,c2 = encryption(pub,m2)
end1 = time.time()

#*****2. MULTIPLICATION OF 2 CIPHERTEXTS ***** 
start2 = time.time()
x_mult,c_mult= multiplication(x1,c1,x2,c2,pub)
end2 = time.time()

#*****3. DECRYPTION ***** 
start3 = time.time()
sms = decryption(priv, x1,c1)
end3 = time.time()

print("\n1. Homomorphic encryption --------------------------------\n")
print("Enc(m1) = (x1,c1) = (", x1,",", c1,")")
print("Result after decryption: m1 = ", sms)
sms = decryption(priv, x2,c2)
print("Enc(m2) = (x2,c2) = (", x2,",", c2,")")
print("Result after decryption: m1 = ", sms)
print("------------------------------------------------------------\n")

sms = decryption(priv, x_mult,c_mult)
print("2. Homomorphic multiplication of 2 ciphertexts -------------\n")
print("Enc(m1 * m2) = (", x_mult,",", c_mult,")")
print("Result after decryption: (m1 * m2) % n = ", sms)
print("------------------------------------------------------------\n")

print( "\n********** PART III: TIME CALCULATION (seconds) ************")
print("")
print("The execution time of Key generation :", end-start)
print("The execution time of Encryption of 2 messages :", end1-start1)
print("The execution time of Multiplication of 2 ciphertexts:", end2-start2)
print("The execution time of a Decryption :", end3-start3)










