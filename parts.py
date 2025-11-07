import utils
from ldei import LDEI
from dleq import DLEQ
from ecpy.curves import Curve, Point
from ecpy.keys import ECPrivateKey, ECPublicKey
from random import randint

class Part:

    # Ordinal number of participant to distinguish properly
    ordinal = -1

    # Keys
    publicKey = -1 # pk -> h**sk
    privateKey = -1 # sk

    # Plain polynom
    polynom = []

    secrets = []
    encryptedSecrets = []
    shares = []
    encryptedShares = []

    dleqShares = []

    # LDEI proof
    computedLDEI = LDEI

    #Elliptic curves
    EC = Curve
    P = Point
    EPK = ECPublicKey # Elliptic Public Key
    ESK = ECPrivateKey # Elliptic Secret Key

    # Initiate participant saving global variables and generating keys USING CICLIC GROUP
    def __init__(self, ordinal: int, t: int, l: int, n: int, q: int, p: int, h: int):
        self.ordinal = ordinal
        self.publicKey, self.privateKey = utils.generateKeys(h, q, p)
        self.polynom = utils.generatePolynom(t, l, q)
        self.secrets, self.encryptedSecrets, self.shares, self.encryptedShares = utils.computePolynom(self.polynom,self.publicKey, l, n, q, p, h)
        auxA, auxE, auxZ = utils.generateLDEI(self.polynom, self.encryptedShares, self.publicKey, n, q, t, l) #TODO: change self.publicKey with publicKey of all participants
        self.computedLDEI = LDEI(auxA, auxE, auxZ)

    # Initiate participant saving global variables and generating keys USING ELLIPTIC CURVES
    def __init__(self, ordinal: int, t: int, l: int, n: int, q: int, p: int, EC: Curve):
        self.ordinal = ordinal
        self.EC = EC
        self.privateKey = randint(1, int(q)-1) # Scalar
        self.ESK = ECPrivateKey(self.privateKey, EC) # Bit redundant as ESK just stores the elliptic curve EC and the scalar self.privateKey
        self.EPK = self.ESK.get_public_key()
        self.polynom = utils.generatePolynom(t, l, q)
        self.shares, self.encryptedShares = utils.computePolynomEC(self.polynom,self.EPK.W, n, q)


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
        return self.ordinal, self.computedLDEI
    

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