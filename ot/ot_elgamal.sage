# Sage Math
import sys

# Compute blood type compatibility from logical operations
"""
 Encoding    +/-   B     A
 ------------------------------
 Recipeint = x2 || x1 || x0
 Donor     = y2 || y1 || y0
"""
def bloodtype_compatibility(x, y):
    x0, x1, x2 = x.digits(base=2, padto=3)
    y0, y1, y2 = y.digits(base=2, padto=3)
    return (1 ^^ (y0 & (1 ^^ x0))) & (1 ^^ (y1 & (1 ^^ x1))) & (1 ^^ (y2 & (1 ^^ x2)))
    

# We use ffdhe2048 group parameter, retrieved from RFC7919 [1].
# The domain parameter (p, q, g) correspond to an approved safe-prime group [2].
#      p = 2q + 1 and ord(g)=q
#
# [1] https://tools.ietf.org/html/rfc7919#appendix-A.1
# [2] Section 5.6.1.1.1 https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf


pstr = """
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

qstr = """
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

gstr = "02"

# 2 encodes f(x,y)=0, and 4 encodes f(x,y)=1
# Both elements are chosen apprpeter.schollopriately so that they belong to an order q cyclic group <g>.
msg_encoding = (2,4)

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
            if gcd(Integer(s),self.p-1) == 1:
                return s^self.r
    
    def sample_from_Zq(self):
        return self.Zq.random_element()

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
  
# OT protocol
class Alice:
    def __init__(self,pp):
        self.pp = pp
        self.x = None
        self.pk = None
        self.sk = None
    
    def Choose(self, x):
        pklist = [None]*8
        self.x = x
        self.sk, self.pk = Gen(pp)
        
        for i in range(8):
            if i == x:
                pklist[i] = self.pk
            else:
                pklist[i] = self.pp.sample_from_G_mul()
        return pklist
    
    def Retrieve(self, clist):
        c0, c1 = clist[self.x]
        m = Dec(c0, c1, self.sk, self.pp)
        if m == 2:
            return 0
        elif m == 4:
            return 1
        else:
            return "Error!"

class Bob:
    def __init__(self,pp):
        self.pp = pp
    
    def Transfer(self, y, pklist):
        # compute outputs f(x,y)=z for all possible x
        mlist = []
        for x in range(8):
            if bloodtype_compatibility(Integer(x),Integer(y)) == 0:
                mlist.append(msg_encoding[0])
            else:
                mlist.append(msg_encoding[1])

        clist = []
        for i, pk in enumerate(pklist):
            clist.append(Enc(pk, pp.Zp(mlist[i]), pp))
        return clist
        
# Main
alice_input = int(sys.argv[1])
bob_input = int(sys.argv[2])
pp = PublicParameter(Integer("0x"+pstr),Integer("0x"+qstr),Integer("0x"+gstr))
A = Alice(pp)
B = Bob(pp)
aout = A.Choose(alice_input)
bout = B.Transfer(bob_input, aout)
print "Securely computed f({0},{1})={2}".format(alice_input, bob_input, A.Retrieve(bout))

# Test ElGamal
m = pp.sample_from_G_mul()
sk, pk = Gen(pp)
c1, c2= Enc(pk,m,pp)
if Dec(c1,c2,sk,pp) == m:
    print "ElGamal is correct."

# Correctness check
e_ctr = 0
for x in range(8):
    for y in range(8):
        A = Alice(pp)
        B = Bob(pp)
        aout = A.Choose(x)
        bout = B.Transfer(y, aout)
        out = A.Retrieve(bout)
        if out != bloodtype_compatibility(Integer(x),Integer(y)):
            e_ctr += 1
print "{} errors occurred.".format(e_ctr)