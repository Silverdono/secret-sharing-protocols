import utils
from ldei import LDEI
from dleq import DLEQ
from ecpy.curves import Curve, Point
from ecpy.keys import ECPrivateKey, ECPublicKey
from random import randint

class Part:

    # Ordinal number of participant to distinguish properly
    ordinal = -1

    #Shared parameters
    n : int
    q : int
    p : int
    t : int
    l : int

    # Keys
    publicKey = -1 # pk -> h**sk
    privateKey = -1 # sk

    # Plain polynomial
    polynomial = []

    shares = []
    encryptedShares = []

    dleqShares = []

    # LDEI proof
    computedLDEI = LDEI

    #Elliptic curves
    EC = Curve
    EPK = ECPublicKey # Elliptic Public Key
    ESK = ECPrivateKey # Elliptic Secret Key

    def __init__(self, ordinal: int, t: int, l: int, n: int, q: int, p: int, h:int, EC: Curve, EC_FLAG:bool):
        if(EC_FLAG):
            # Initiate participant saving global variables and generating keys USING ELLIPTIC CURVES
            self.ordinal = ordinal
            self.EC = EC
            q = self.EC._domain["order"]
            self.q = self.EC._domain["order"]
            self.privateKey = randint(1, int(q)-1) # Scalar
            self.ESK = ECPrivateKey(self.privateKey, EC) # Bit redundant as ESK just stores the elliptic curve EC and the scalar self.privateKey
            self.EPK = self.ESK.get_public_key()
            self.polynomial = utils.generatePolynomial(t, l, q)
            self.shares, self.encryptedShares = utils.computePolynomialEC(self.polynomial,self.EPK.W, n, q)
        else:
            # Initiate participant saving global variables and generating keys USING CICLIC GROUP
            self.ordinal = ordinal
            self.n = n
            self.q = q
            self.p = p
            self.t = t
            self.l = l
            self.publicKey, self.privateKey = utils.generateKeys(h, q, p)
            self.polynomial = utils.generatePolynomial(t, l, q)
            self.shares, self.encryptedShares = utils.computePolynomial(self.polynomial,self.publicKey, l, n, q, p)

    def generateLDEI(self, pks: list[int]):
        auxA, auxE, auxZ = utils.generateLDEI(self.polynomial, self.encryptedShares, pks, self.n, self.q, self.p, self.t, self.l)
        self.computedLDEI = LDEI(auxA, auxE, auxZ)

    def generateLDEI_EC(self, pks: list[Point]):
        auxA, auxE, auxZ = utils.generateLDEI_EC(self.polynomial, self.encryptedShares, pks, self.n, self.q, self.p, self.t, self.l)
        self.computedLDEI = LDEI(auxA, auxE, auxZ)

    # Return the ordinal number of the participant and his public key
    def sendPublicKey(self):
        return self.ordinal, self.publicKey
    
    # Return the ordinal number of the participant and his public key from an EC
    def sendPublicKeyEC(self):
        return self.ordinal, self.EPK

    # Return the ordinal number of the participant and his encrypted shares
    def sendEncryptedShares(self):
        return self.ordinal, self.encryptedShares
    
    # Return the ordinal number of the participant and his ldei
    def sendLDEI(self):
        if(self.computedLDEI != None):   
            return self.ordinal, self.computedLDEI
        else:
            return None
        
    # Return plain shares    
    def sendShares(self):
        return self.ordinal, self.shares    
    

    # Compute DLEQ proof for himself
    def computeDLEQ(self, q: int):
        self.dleqShares = []
        invSk = pow(self.privateKey, -1, q)
        for share in self.encryptedShares:
            self.dleqShares.append(pow(share, invSk, q))

        w = randint(0, q) #References we found use a random number mod q
        a = []
        for share in self.encryptedShares:
            a.append(pow(share, w, q))

        # We use "custom" hash function because lists are not hashable    
        e = (sum((a[i] * self.dleqShares[i] * self.encryptedShares[i]) for i in range(0, len(a)))) % q

        temp = (invSk * e) % q
        z = (w - temp) % q 

        return DLEQ(a, e, z)