# The encryption of Paillier (1999) is an additively homomorphic cryptosystem, 
# which is based on the composite residuosity problem 
# and gathers many good properties.

# This is a simple demonstration of Paillier homomorphic encryption, 
# well known as a Partial Homomorphic Encryption (PHE)
# Here we attempts to show the basic mathematical operations
# that can be performed on both ciphertexts and plaintexts.


import math
from Crypto.Util.number import *
import gmpy2
import time

def gcd(a,b): 
    while b > 0:
        a, b = b, a % b
    return a

def int_time():
    return int(round(time.time() * 1000000)) 

# Generating a number randomly which is co-prime to n    
def rd_number(n):
	state = gmpy2.random_state(int_time())
	r = gmpy2.mpz_random(state,n)
	while gmpy2.gcd(r,n) != 1: 
		state = gmpy2.random_state(int_time())
		r = gmpy2.mpz_random(state,n)
	return r
	
class PrivateKey():
    def __init__(self, bits):
        equal=True
        while equal:
            self.p = getPrime(bits // 2)
            self.q = getPrime(bits // 2)
            if (self.p!=self.q):
                equal = False
    def display_value(self):
        return f'p = {self.p} \nq = {self.q}'
            
class PublicKey():
    def __init__(self, p,q):
       self.n=p*q
       self.n_sq = self.n * self.n
       
    def display_value(self):
        return f'n = {self.n} \nn_sq = {self.n_sq}'
     
def key_generation(priv,pub):  
    phi_n = (priv.p-1)*(priv.q-1)
    rho=gmpy2.invert(pub.n, phi_n) 
    return rho

# Encrypting a plaintext m using public keys
def encryption(pub, m):
    r = rd_number(pub.n)
    x = gmpy2.powmod(r,pub.n,pub.n_sq)
    y = gmpy2.f_mod(gmpy2.add(gmpy2.mul(m,pub.n),1),pub.n_sq)
    cipher = gmpy2.f_mod(gmpy2.mul(y,x),pub.n_sq)
    return cipher

# Decrypting a ciphertext using secret keys
def decryption(rho, cipher, pub):
    r0 = gmpy2.powmod(cipher,rho,pub.n)
    x = gmpy2.powmod(r0,pub.n,pub.n_sq)
    x_inv = gmpy2.invert(x, pub.n_sq)
    temp = gmpy2.f_mod(gmpy2.mul(cipher,x_inv),pub.n_sq) 
    m = gmpy2.sub(temp,1)
    m = gmpy2.divexact(m,pub.n)    
    m = gmpy2.mpz(m)   
    return m, r0

# Homomorphic addition of 2 ciphertexts: ct0 and ct1	
def addition(ct0,ct1,pub):
	ct=gmpy2.f_mod(gmpy2.mul(ct0,ct1),pub.n_sq)
	return ct

# Homomorphic substraction of 2 ciphertexts
#def substraction(ct0,ct1,pub):
#	 ct1_inv = gmpy2.invert(ct1, pub.n_sq)	
#	 ct=gmpy2.f_mod(gmpy2.mul(ct0,ct1_inv),pub.n_sq)
#	 return ct

# Homomorphic addition of 3 ciphertexts: ct0, ct1, and ct2
def addition_of_3(ct0,ct1,ct2,pub):
	ct=gmpy2.f_mod(gmpy2.mul(ct0,ct1),pub.n_sq)
	ct=gmpy2.f_mod(gmpy2.mul(ct,ct2),pub.n_sq)
	return ct

# Homomorphic multiplication of a ciphertext to a plaintext	
def mult_plain(ct,plain,pub):
	c=gmpy2.powmod(ct,plain,pub.n_sq)
	return c

# In fact, Paillier cryptosystem is a PHE which operates
# only addition operation on ciphertexts. However, we can transform them into Fully/Somewhat HE
# by adding a Zero-knowledge (zk_multProof) step.

# Suppose we have 2 parties: Alice (provider) and Bob (verifier).
# Alice has 2 ciphertexts Enc(x) and Enc(y) and wants to calculate E(x*y) without knowing
# secret keys. Bob has secret keys but he can't reveal them.
# zk_multProof function not only helps Bob and Alice communicate to get the value of E(x*y) without revealing 
# the info of secrets, but also ensure that no one can cheat and/or give false infomation.
def zk_multProof(sy,xr, X, Y, Z):
	
	# 1. Bob does:	
	state = gmpy2.random_state(int_time())
	a = gmpy2.mpz_random(state,pub.n)
	A = encryption(pub, a)
	ay = gmpy2.f_mod(gmpy2.mul(a,sy), pub.n)
	B = encryption(pub, ay)
	
	# 2. Alice does:
	e = rd_number(pub.n)
	
	# 3. Bob does:	
	XeA = addition(mult_plain(X,e,pub), A,pub)
	c,r = decryption(rho, XeA, pub)
	
	B_inv =gmpy2.invert(B, pub.n_sq)
	YcB = addition(mult_plain(Y,c,pub), B_inv,pub) 
	Ze_inv = gmpy2.invert(mult_plain(Z,e,pub), pub.n_sq)
	YcBZ = addition(YcB, Ze_inv, pub)
	d,r0 = decryption(rho, YcBZ, pub)
	
	# 4. Alice does:	
	is_valid = True
	temp = gmpy2.f_mod(gmpy2.mul(c,pub.n), pub.n_sq)
	temp = temp +1
	XeA_cmp = gmpy2.powmod(r,pub.n,pub.n_sq)
	XeA_cmp = gmpy2.f_mod(gmpy2.mul(XeA_cmp,temp), pub.n_sq)
	
	r0_cmp = gmpy2.powmod(r0,pub.n,pub.n_sq)
	if (XeA_cmp != XeA or r0_cmp != YcBZ):
		is_valid = False		
	return is_valid

# Homomorphic multiplication of 2 ciphertexts
# Zero-knowledge proof can be applied to find E(ex + ey) as follows:
def mult_ct(ex, ey, pub, priv):

	# 1.Alice does:
	#  1.1 random r, s	
	state = gmpy2.random_state(int_time())
	r = gmpy2.mpz_random(state,pub.n)
	state = gmpy2.random_state(int_time())
	s = gmpy2.mpz_random(state,pub.n)
	
    #  1.2 calc E(r+x), E(s+y)
	er = encryption(pub,r)
	es = encryption(pub,s)
	rx_enc = addition(er,ex,pub)
	sy_enc = addition(es,ey,pub)
    	
    # 2. Bob does:
    #  2.1. decrypt E(r+x), E(s+y) 
	rho=key_generation(priv,pub)
	rx_dec, r0 = decryption(rho,rx_enc, pub)
	sy_dec, r0 = decryption(rho,sy_enc, pub)

    #  2.2 calc E((x+r)(y+s))
	rx_mult_sy = gmpy2.f_mod(gmpy2.mul(rx_dec,sy_dec),pub.n)
	enc_rx_sy = encryption(pub,rx_mult_sy)
	
    # B and A: check ZKproof valid
	is_valid = zk_multProof(sy_dec,rx_dec, rx_enc, sy_enc, enc_rx_sy)
    	
    # 3. Alice finishes by returning enc_xy = Enc(ex+ey): 
	enc_xy =0
	if  is_valid: 
		rs = gmpy2.f_mod(gmpy2.mul(r,s), pub.n)
		enc_rs = encryption(pub,rs)
		enc_ry = mult_plain(ey,r,pub)
		enc_sx = mult_plain(ex,s,pub)
		sum_3=addition_of_3(enc_rs,enc_ry,enc_sx,pub)
		sum_3_inv =gmpy2.invert(sum_3, pub.n_sq)
		enc_xy = addition(enc_rx_sy,sum_3_inv,pub)
	return enc_xy, is_valid

# Homomorphic average of several number of ciphertexts (nb)    	
def avg(c_sum, nb, pub):	
	nb_inv =  gmpy2.invert(nb, pub.n)
	c=gmpy2.powmod(c_sum,nb_inv,pub.n_sq)
	m_sum, r0= decryption(rho,c, pub)
	[u1, u2] = [0, pub.n] 
	[v1, v2] = [1, m_sum]
	while (u2 > math.sqrt(pub.n)):
   		Q = u2 // v2
   		[t1, t2] = [u1-v1*Q,u2-v2*Q]
   		[u1, u2] = [v1, v2]
   		[v1, v2] = [t1, t2]
	return u2/u1


print("\n*********************************************************")
print("\n*         Paillier cryptosystem demonstration           *")
print("\n*********************************************************")
print("")

# Key size should be at least 256 bits to ensure the system's security and accuracy.
print('Please enter a Paillier key size in bits and hit enter:')
try:
	bits = int(input())
except ValueError:
	print("Please enter an integer, e.g. 256, 512, etc.")
	exit()

print( "\n\n**************** PART I: KEY GENERATION *******************")
start = time.time()
priv=PrivateKey(bits)
pub=PublicKey(priv.p,priv.q)
rho=key_generation(priv,pub)
end = time.time()
print("key_size = ", bits)
print(priv.display_value())
print(pub.display_value())

print( "\n\n************ PART II: HOMOMORPHIC OPERATIONS **************")
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
start = time.time()
ct1=encryption(pub,m1)
ct2=encryption(pub,m2)
end = time.time()

#*****2. ADDITION *****
start1 = time.time()
c_add=addition(ct1,ct2,pub)
end1 = time.time()

#*****3. MULTIPLY a CIPHERTEXT to a PLAINTEXT ***** 
plain = 2
start3 = time.time()
c_mult_plain = mult_plain(ct1,plain,pub)
end3 = time.time()

#*****4. MULTIPLICATION OF 2 CIPHERTEXTS ***** 
start4 = time.time()
c_mult, valid = mult_ct(ct1, ct2, pub, priv)
end4 = time.time()

#*****5. AVERAGE OF 2 CIPHERTEXTS ***** 
start6 = time.time()
c_avg = avg(c_add, 2,pub)
end6 = time.time()

#*****6. DECRYPTION ***** 
start5 = time.time()
sms, r0= decryption(rho,c_add, pub)
end5 = time.time()

print("\n1. Homomorphic addition ------------------------------------\n")
print("Enc(m1) + Enc(m2) = Enc(m1 + m2) = ", c_add)
print("Result after decryption: m1 + m2 = ", sms)
print("------------------------------------------------------------\n")

sms, r0= decryption(rho,c_mult_plain, pub)
print("2. Homomorphic multiplication to a plaintext ---------------\n")
print("Enc(m1)²= Enc(m1 * 2) = ", c_mult_plain)
print("Result after decryption: m1 * 2 = ", sms)
print("------------------------------------------------------------\n")

sms, r0= decryption(rho,c_mult, pub)
print("3. Homomorphic multiplication of 2 ciphertexts -------------\n")
print("Enc(m1 * m2) = ", c_mult)
print("Result after decryption: (m1 * m2) % n = ", sms)
print("------------------------------------------------------------\n")

print("4. Homomorphic average of 2 ciphertexts --------------------\n")
print("Result of Average of 2 Ciphertexts after decryption: (m1 + m2)/2 = ", c_avg)
print("------------------------------------------------------------\n")



print( "\n************ PART III: TIME CALCULATION (seconds) ***********")
print("")
print("The execution time of Key generation :", end-start)
print("The execution time of Encryption of 2 messages :", end-start)
print("The execution time of Addition of 2 messages :", end1-start1)
print("The execution time of Multiplication to a plaintext:", end3-start3)
print("The execution time of Multiplication of 2 ciphertexts:", end4-start4)
print("The execution time of a Decryption :", end5-start5)
print("The execution time of calculating an average :", end6-start6)




