#!/usr/bin/sage

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

# DGHV scheme
# Compute y_i = p*q_i + r_i for 0<=i<=n
def Gen(p_bit, q_bit, r_bit, n):
    p = ZZ.random_element(2^(p_bit-1),2^p_bit)
    while Mod(p, 2) == 0:
        p = ZZ.random_element(2^(p_bit-1),2^p_bit)
        
    pk = []
    for i in range(n):
        q = ZZ.random_element(2^(q_bit-1),2^q_bit)
        r = ZZ.random_element(2^(r_bit-1),2^r_bit)    
        pk.append(p*q + 2*r)
    
    return (p, pk)

def Enc(m, pk):
    c = m
    SS = Subsets(range(len(pk)))
    while(1):
        S = SS.random_element()
        if len(S) != 0:
            break
    for i in S:
        c += pk[i]
        
    return c

def Dec(c, sk):
    return Mod(Mod(c, sk), 2)

# 2PC based on FHE
class Alice:
    def __init__(self, p_bit, q_bit, r_bit, n):
        self.sk, self.pk = Gen(p_bit, q_bit, r_bit, n)
    
    def Choose(self, xint):
        # Process the input value
        self.x = Integer(xint).digits(base=2, padto=3)
        c = []
        for i in range(3):
            c.append(Enc(self.x[i], self.pk))
        
        return (c, self.pk)
    
    def Retrieve(self, c):
        return Dec(c, self.sk)
        
class Bob:
    def __init__(self):
        pass
    
    def Transfer(self, yint, c_x, pk):
        # Process the input value
        y = Integer(yint).digits(base=2, padto=3)
        c_y = []
        c1 = Enc(1, pk)
        for i in range(3):
            c_y.append(Enc(y[i], pk))
        
        return ((c1 + (c_y[0]*(c1 + c_x[0]))) * (c1 + (c_y[1]*(c1 + c_x[1]))) * (c1 + (c_y[2]*(c1 + c_x[2]))))

# Each encryption introduces approximately O(|r|+log(n))-bit of noise.
# This means that the noise after computing the circuit of multiplication
# depth d will be around O((|r|+log(n))*2^d)-bit.
# The parameters below are set such that the noise for d=3 is still sufficiently
# smaller than |p|.
p_bit = 256
q_bit = 1000
r_bit = 10
n = 128

# Main
alice_input = int(sys.argv[1])
bob_input = int(sys.argv[2])
A = Alice(p_bit, q_bit, r_bit, n)
B = Bob()
c, pk = A.Choose(alice_input)
cc = B.Transfer(bob_input, c, pk)
out = A.Retrieve(cc)
print "Securely computed f({0},{1})={2}".format(alice_input, bob_input, out)

# Test
e_ctr = 0
print "Testing correctness.."
for x in range(8):
    for y in range(8):
        A = Alice(p_bit, q_bit, r_bit, n)
        B = Bob()
        c, pk = A.Choose(x)
        cc = B.Transfer(y, c, pk)
        out = A.Retrieve(cc)
        #print "Securely computed f({0},{1})={2}".format(x, y, out)
        if out != bloodtype_compatibility(x, y):
            e_ctr += 1

print "{} errors occurred.".format(e_ctr)
