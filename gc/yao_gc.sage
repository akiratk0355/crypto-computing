#!/usr/bin/sage

import sys
import hashlib
import copy

# Compute blood type compatibility from logical operations
"""
 Encoding    +/-   B     A
 ------------------------------
 Recipient = x2 || x1 || x0
 Donor     = y2 || y1 || y0
"""
def bloodtype_compatibility(x, y):
    x0, x1, x2 = Integer(x).digits(base=2, padto=3)
    y0, y1, y2 = Integer(y).digits(base=2, padto=3)
    return (1 ^^ (y0 & (1 ^^ x0))) & (1 ^^ (y1 & (1 ^^ x1))) & (1 ^^ (y2 & (1 ^^ x2)))


# Public Parameters and Constants

# We use ffdhe2048 group parameter, retrieved from RFC7919 [1].
# The domain parameter (p, q, g) correspond to an approved safe-prime group [2].
#      p = 2q + 1 and ord(g)=q
#
# [1] https://tools.ietf.org/html/rfc7919#appendix-A.1
# [2] Section 5.6.1.1.1 https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf

ST_p = """
    FFFFFFFF FFFFFFFF ADF85458 A2BB4A9A AFDC5620 273D3CF1
    D8B9C583 CE2D3695 A9E13641 146433FB CC939DCE 249B3EF9
    7D2FE363 630C75D8 F681B202 AEC4617A D3DF1ED5 D5FD6561
    2433F51F 5F066ED0 85636555 3DED1AF3 B557135E 7F57C935
    984F0C70 E0E68B77 E2A689DA F3EFE872 1DF158A1 36ADE735
    30ACCA4F 483A797A BC0AB182 B324FB61 D108A94B B2C8E3FB
    B96ADAB7 60D7F468 1D4F42A3 DE394DF4 AE56EDE7 6372BB19
    0B07A7C8 EE0A6D70 9E02FCE1 CDF7E2EC C03404CD 28342F61
    9172FE9C E98583FF 8E4F1232 EEF28183 C3FE3B1B 4C6FAD73
    3BB5FCBC 2EC22005 C58EF183 7D1683B2 C6F34A26 C1B2EFFA
    886B4238 61285C97 FFFFFFFF FFFFFFFF"""

ST_q = """
    7FFFFFFF FFFFFFFF D6FC2A2C 515DA54D 57EE2B10 139E9E78
    EC5CE2C1 E7169B4A D4F09B20 8A3219FD E649CEE7 124D9F7C
    BE97F1B1 B1863AEC 7B40D901 576230BD 69EF8F6A EAFEB2B0
    9219FA8F AF833768 42B1B2AA 9EF68D79 DAAB89AF 3FABE49A
    CC278638 707345BB F15344ED 79F7F439 0EF8AC50 9B56F39A
    98566527 A41D3CBD 5E0558C1 59927DB0 E88454A5 D96471FD
    DCB56D5B B06BFA34 0EA7A151 EF1CA6FA 572B76F3 B1B95D8C
    8583D3E4 770536B8 4F017E70 E6FBF176 601A0266 941A17B0
    C8B97F4E 74C2C1FF C7278919 777940C1 E1FF1D8D A637D6B9
    9DDAFE5E 17611002 E2C778C1 BE8B41D9 6379A513 60D977FD
    4435A11C 30942E4B FFFFFFFF FFFFFFFF"""

ST_g = "02"
NBITS_K = 128
NBYTES_K = NBITS_K//8
NHEX_K = NBITS_K//4
K00 = '0'^(NBYTES_K*2)
INT_K00 = Integer(2^NBITS_K)
ST_0x = '0x'
T_IN = "IN";  T_AND = "AND"; T_XOR = "XOR"; T_NAND = "NAND"

class PublicParameter:
    def __init__(self, p, q, g):
        self.Zp= Zmod(p)
        self.Zq= Zmod(q)
        self.p = p
        self.q = q
        if mod(p,q) != 1:
            print "Error"
        self.r = (p-1)/q
        self.g = self.Zp(g)
    
    # This also works as OGen
    def sample_from_G_mul(self):
        while True:
            s = self.Zp.random_element()
            #if gcd(Integer(s),self.p-1) == 1:
            return s^self.r
    
    def sample_from_Zq(self):
        return self.Zq.random_element()
    
    # Utility function that maps hex string to a group element in G = <g>.
    # As p = 2q+1, the order q subgroup of Z_p^* consists of 
    # non-zero quadratic residues modulo p, and hence the following method works.
    def encode_msg(self, m):
        return self.Zp(Integer(m)^self.r)
    
    def decode_msg(self, m):
	#return Integer(sqrt(self.Zp(m))) # This was slow..
	cand1 = self.Zp(m)^((self.p+1)//4) # This is much faster for safe primes
        cand2= -cand1
        return min(Integer(cand1), Integer(cand2))

# ElGamal PKE
def Gen(pp):
    sk = pp.sample_from_Zq()
    pk = pp.g^sk
    return (sk,pk)

def Enc(pk,m,pp):
    k = pp.sample_from_Zq()
    c0 = pp.g^k
    c1 = m*(pk^k)
    return (c0,c1)

def Dec(c0,c1,sk,pp):
    return c1/(c0^sk)

# PRF
# return value is Integer
def PRF(Kl, Kr, i):
    return Integer('0x'+hashlib.sha256(Kl+Kr+str(i)).hexdigest())

# Circuit Garbling
class Gate:
    def __init__(self, id, type, id_l, id_r, is_out=False, is_Ain=False, is_Bin=False):
        self.id = id
        self.type = type
        self.id_l = id_l
        self.id_r = id_r        
        self.is_out = is_out
        self.is_Ain = is_Ain
        self.is_Bin = is_Bin
        
        self.keys = None
        self.table = []
        self.is_garbled = False

class Circuit(dict):
    def __init__(self):
        self = dict()
    
    def add_gate(self, id, type, id_l, id_r, **kwargs):
        self[id] = Gate(id, type, id_l, id_r, **kwargs)
    
    def garble(self):
        for gid, g in sorted(self.iteritems()):
            #print "garbling gate {0}, type={1}".format(gid, g.type)
            # Key generation
            Ko0 = os.urandom(NBYTES_K).encode('hex')
            Ko1 = os.urandom(NBYTES_K).encode('hex')
            if g.type != T_IN:
                if not self[g.id_l].is_garbled:
                    raise Exception("Gate {} is not garbled yet".format(g.id_l))
                if not self[g.id_r].is_garbled:
                    raise Exception("Gate {} is not garbled yet".format(g.id_r))
                Kl0 = self[g.id_l].keys[0]
                Kl1 = self[g.id_l].keys[1]
                Kr0 = self[g.id_r].keys[0]
                Kr1 = self[g.id_r].keys[1]

            # Define a garbled table
            if g.type == T_NAND:
                C00 = PRF(Kl0, Kr0, gid) ^^ Integer(ST_0x+Ko1+K00)
                C01 = PRF(Kl0, Kr1, gid) ^^ Integer(ST_0x+Ko1+K00)
                C10 = PRF(Kl1, Kr0, gid) ^^ Integer(ST_0x+Ko1+K00)
                C11 = PRF(Kl1, Kr1, gid) ^^ Integer(ST_0x+Ko0+K00)
            elif g.type == T_AND:
                C00 = PRF(Kl0, Kr0, gid) ^^ Integer(ST_0x+Ko0+K00)
                C01 = PRF(Kl0, Kr1, gid) ^^ Integer(ST_0x+Ko0+K00)
                C10 = PRF(Kl1, Kr0, gid) ^^ Integer(ST_0x+Ko0+K00)
                C11 = PRF(Kl1, Kr1, gid) ^^ Integer(ST_0x+Ko1+K00)
            elif g.type == T_XOR:
                C00 = PRF(Kl0, Kr0, gid) ^^ Integer(ST_0x+Ko0+K00)
                C01 = PRF(Kl0, Kr1, gid) ^^ Integer(ST_0x+Ko1+K00)
                C10 = PRF(Kl1, Kr0, gid) ^^ Integer(ST_0x+Ko1+K00)
                C11 = PRF(Kl1, Kr1, gid) ^^ Integer(ST_0x+Ko0+K00)
            elif g.type == T_IN: # dummy
                C00 = None; C01 = None; C10 = None; C11 = None
            else:
                raise Exception("Unsupported gate type {}".format(g.type))

            g.table = Permutations([C00, C01, C10, C11]).random_element()
            g.keys = [Ko0, Ko1]
            g.is_garbled = True
        
    def encode(self, input_B, keylist_A, pp):
        # Process input
        i = 0 
        j = 0
        for gid, g in sorted(self.iteritems()): # assuming the least significant input bit comes first
            if g.is_Bin:
                g.keys[0] = g.keys[input_B[i]]
                g.keys[1] = None
                i += 1
            elif g.is_Ain:
                g.keys[0] = Enc(keylist_A[j][0], pp.encode_msg(ST_0x+g.keys[0]), pp)
                g.keys[1] = Enc(keylist_A[j][1], pp.encode_msg(ST_0x+g.keys[1]), pp)
                j += 1
            elif g.is_out:
                pass
            else:
                g.keys = [None, None]
        
        if len(keylist_A) != j:
            raise Exception("The number of OTs doesn't match input wires")
    
    def decode(self, Z, gid):
        if Integer(ST_0x+self[gid].keys[0]) == Z:
            return 0
        elif Integer(ST_0x+self[gid].keys[1]) == Z:
            return 1
        else:
            raise Exception("Decoding failed!")        
    
    def evaluate(self):
        for gid, g in sorted(self.iteritems()):
            #print "Evaluating the gate {}".format(gid)
            if g.type != T_IN:
                H = PRF(self[g.id_l].keys[0], self[g.id_r].keys[0], gid)
                for C in g.table:
                    K_cand = C^^H
                    if Mod(K_cand, INT_K00) == 0:
                        if g.is_out:
                            return self.decode(K_cand//INT_K00, gid)
                        else:
                            g.keys[0] = '{0:0{1}x}'.format(K_cand//INT_K00, NHEX_K) 
                            break

# Yao's 2PC
class Alice:
    def __init__(self, pp):
        self.pp = pp
        self.x = []
        self.sklist = []
    
    def Choose(self, xint):
        # Process the input value
        pksent = [[0,0],[0,0],[0,0]]
        self.x = Integer(xint).digits(base=2, padto=3)
        
        # Key generation
        for i in range(3):
            sk, pk = Gen(self.pp)
            self.sklist.append(sk)
            # precompute xor with her own input
            pksent[i][int(self.x[i])^^1] = pk
            pksent[i][int(self.x[i])] = self.pp.sample_from_G_mul()
        
        return pksent
    
    def Retrieve(self, gc):
        i = 0
        # Retrieving input keys
        for gid, g in sorted(gc.iteritems()):
            if g.is_Ain:
                c0, c1 = g.keys[self.x[i]^^1]
                K = self.pp.decode_msg(Dec(c0, c1, self.sklist[i], self.pp))
                g.keys[0] = '{0:0{1}x}'.format(K, NHEX_K)
                g.keys[1] = None
                i += 1

        return gc.evaluate()
        
class Bob:
    def __init__(self, pp, c):
        self.pp = pp
        self.circuit = c
        self.circuit.garble()
        
    def Transfer(self, yint, pks):
        # Process the input value
        y = Integer(yint).digits(base=2, padto=3)
        self.circuit.encode(y, pks, self.pp)
        return self.circuit       

# Main
alice_input = int(sys.argv[1])
bob_input = int(sys.argv[2])
pp = PublicParameter(Integer(ST_0x+ST_p),Integer(ST_0x+ST_q),Integer(ST_0x+ST_g))

C = Circuit()
C.add_gate(1, T_IN, 0, 0, is_Ain=True)
C.add_gate(2, T_IN, 0, 0, is_Ain=True)
C.add_gate(3, T_IN, 0, 0, is_Ain=True)
C.add_gate(4, T_IN, 0, 0, is_Bin=True)
C.add_gate(5, T_IN, 0, 0, is_Bin=True)
C.add_gate(6, T_IN, 0, 0, is_Bin=True)
C.add_gate(7, T_NAND, 4, 1)
C.add_gate(8, T_NAND, 5, 2)
C.add_gate(9, T_NAND, 6, 3)
C.add_gate(10, T_AND, 7, 8)
C.add_gate(11, T_AND, 10, 9, is_out=True)

A = Alice(pp)
B = Bob(pp,C)
pks = A.Choose(alice_input)
gc = B.Transfer(bob_input, pks)
out = A.Retrieve(gc)
print "Securely computed f({0},{1})={2}".format(alice_input, bob_input, out)

# Test ElGamal
m = pp.sample_from_G_mul()
sk, pk = Gen(pp)
c1, c2= Enc(pk,m,pp)
if Dec(c1,c2,sk,pp) == m:
    print "ElGamal is correct."
else:
    print "ElGamal failed!"

# Correctness check
e_ctr = 0
print "Testing Yao's 2PC correctness.."
for x in range(8):
    for y in range(8):
        C = Circuit()
        C.add_gate(1, T_IN, 0, 0, is_Ain=True)
        C.add_gate(2, T_IN, 0, 0, is_Ain=True)
        C.add_gate(3, T_IN, 0, 0, is_Ain=True)
        C.add_gate(4, T_IN, 0, 0, is_Bin=True)
        C.add_gate(5, T_IN, 0, 0, is_Bin=True)
        C.add_gate(6, T_IN, 0, 0, is_Bin=True)
        C.add_gate(7, T_NAND, 4, 1)
        C.add_gate(8, T_NAND, 5, 2)
        C.add_gate(9, T_NAND, 6, 3)
        C.add_gate(10, T_AND, 7, 8)
        C.add_gate(11, T_AND, 10, 9, is_out=True)

        A = Alice(pp)
        B = Bob(pp,C)
        pks = A.Choose(x)
        gc = B.Transfer(y, pks)
        out = A.Retrieve(gc)
        #print "Securely computed f({0},{1})={2}".format(x, y, out)
        if out != bloodtype_compatibility(x, y):
            e_ctr += 1

print "{} errors occurred.".format(e_ctr)
