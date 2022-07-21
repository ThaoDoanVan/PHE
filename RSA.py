# RSA was first introduced by Rivest et al. in 1978. 
# The security of the cryptosystem relies on the practical hardness of
# factoring the product of two large prime numbers, called the factoring problem. 

# In homomorphic encryption (HE), RSA is the first Partial Homomorphic Encryption (PHE)
# and commonly used in practice. Compared to other HE schemes such as Paillier and El-Gamal,
# RSA is much easier. Here we demonstrate a simple program of RSA 
# and its multiplicatively homomorphic properties.

import random
import time
import gmpy2
from Crypto.Util.number import *

class PrivateKey():
	def __init__(self, bits):
		equal=True
		while equal:
            		self.p = getPrime(bits // 2)
            		self.q = getPrime(bits // 2)
            		if (self.p!=self.q):
                		equal = False

	def GenKeyPair(self):
		phi = (self.p-1)*(self.q-1) 
		e = getPrime(18)	 # e = prime 18 bots 
		self.d = gmpy2.invert(e,phi)
		while (gmpy2.gcd(self.d,phi) != 1):
			e = getPrime(18)	 # e = prime 18 bots 
			self.d = gmpy2.invert(e,phi)   
		return e, self.d    
	def display_value(self):
		return f'p = {self.p} \nq = {self.q} \nd = {self.d} \ne = {e}' 
                   
class PublicKey():
	def __init__(self,p,q):
		self.n = p*q 
	def display_value(self):
		return f'n = {self.n}'       

# Encrypting a plaintext m using public keys
def encryption(pub,m):
	c = gmpy2.powmod(m,e,pub.n) 	
	return c

# Decrypting a ciphertext c using secret keys
def decryption(priv, c):
	sms = gmpy2.powmod(c,priv.d,pub.n) 	
	return sms 

# Homomorphic multiplication of 2 ciphertexts 		
def multiplication(c1,c2, pub):	
	c= gmpy2.f_mod(gmpy2.mul(c1,c2),pub.n)	
	return c
		
print("\n*********************************************************")
print("\n*            RSA cryptosystem demonstration             *")
print( "\n*********************************************************")
print("")

print('Please enter a RSA key size in bits and hit enter:')
try:
	bits = int(input())
except ValueError:
	print("Please enter an integer, e.g. 256, 512, etc.")
	exit()

print( "\n\n*************** PART I: KEY GENERATION ******************")

start = time.time()
priv = PrivateKey(bits)
e,d = priv.GenKeyPair()
pub = PublicKey(priv.p, priv.q)
end = time.time()
print("key_size = ", bits)
print(priv.display_value())
print(pub.display_value())

print( "\n\n*********** PART II: HOMOMORPHIC OPERATIONS *************")
print("")
print('Please enter the first message (m1 < n) :')
try:
	m1 = int(input())
except ValueError:
	print("Please enter integer numbers.")
	exit()
print('Please enter the second message (m2 < n) :')
try:
	m2 = int(input())
except ValueError:
	print("Please enter integer numbers.")
	exit()		
print("m1 = ", m1, "\nm2 = ",m2)

#*****1. ENCRYPTION *****
start1=time.time()
c1 = encryption(pub,m1)
c2 = encryption(pub,m2)
end1 = time.time()

#*****2. MULTIPLICATION OF 2 CIPHERTEXTS ***** 
start2 = time.time()
c_mult = multiplication(c1,c2, pub)
end2 = time.time()

#*****3. DECRYPTION ***** 
start3 = time.time()
sms = decryption(priv,c1)
end3 = time.time()


print("\n1. Homomorphic encryption --------------------------------\n")
print("Enc(m1) = ", c1)
print("Result after decryption: m1 = ", sms)
sms = decryption(priv,c2)
print("Enc(m2) = ", c2)
print("Result after decryption: m1 = ", sms)
print("------------------------------------------------------------\n")

sms = decryption(priv, c_mult)
print("2. Homomorphic multiplication of 2 ciphertexts -------------\n")
print("Enc(m1 * m2) = ", c_mult)
print("Result after decryption: (m1 * m2) % n = ", sms)
print("------------------------------------------------------------\n")

print( "\n********** PART III: TIME CALCULATION (seconds) ************")
print("")
print("The execution time of Key generation :", end-start)
print("The execution time of Encryption of 2 messages :", end1-start1)
print("The execution time of Multiplication of 2 ciphertexts:", end2-start2)
print("The execution time of a Decryption :", end3-start3)




       
