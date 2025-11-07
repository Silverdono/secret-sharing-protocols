from random import randint
from ecpy.curves import Curve
from ldei import LDEI
import utils

class Ledger:

    # Defining global variable for the ledger
    nParticipants = -1  # n
    tolerance = -1      # t
    sizeDomain = -1     # p
    order = -1          # q
    generator = -1      # h
    l = -1              # l

    w = -1 # w for Vandermonde matrix

    EC : Curve = None # Elliptic curve

    publicKeys = []
    ldeis = []
    shares = []

    decryptedShares = []

    recoPartOrdinal = [] # Reconstruction participants' ordinal

    def __init__(self, n: int, p: int, elliptic: bool):
        self.nParticipants = n
        self.sizeDomain = p
        self.generator = utils.findGenerator(p)
        self.order = utils.findMultiplicativeOrder(self.generator,p)

        self.w = randint(0, self.order)

        if(elliptic):
            self.EC = Curve.get_curve('secp256k1')

        self.tolerance = int(n/3) # A bit arbitrary this value
        self.l = int(n - 2 * self.tolerance)


    def addPublicKey(self, ordinal:int, pk: int):
        if len(self.publicKeys) < ordinal:
            for i in range(len(self.publicKeys)-1, ordinal-1):
                self.publicKeys.append(None)
                self.publicKeys.append(pk)
        elif len(self.publicKeys) == ordinal:
            self.publicKeys.append(pk)
        else :   
            self.publicKeys[ordinal] = pk
                

    def addShares(self, ordinal:int, shares: list):
        if len(self.shares) < ordinal:
            for i in range(len(self.shares)-1, ordinal-1):
                self.shares.append(None)
                self.shares.append(shares)
        elif len(self.shares) == ordinal:
            self.shares.append(shares)
        else :   
            self.shares[ordinal] = shares

    def addDecryptedShares(self, shares: list):
        self.decryptedShares.append(shares)

    def addLDEI(self, ordinal:int, ldei: LDEI):
        if len(self.ldeis) < ordinal:
            for i in range(len(self.ldeis)-1, ordinal-1):
                self.ldeis.append(None)
                self.ldeis.append(ldei)
        elif len(self.ldeis) == ordinal:
            self.ldeis.append(ldei)
        else :   
            self.ldeis[ordinal] = ldei


    def getT(self) -> int:
        return self.tolerance

    def getL(self) -> int:
        return self.l            
    
    def getGenerator(self) -> int:
        return self.generator
    
    def getEC(self) -> Curve | None:
        return self.EC
    
    def getOrder(self) -> int:
        return self.order

    def addRecoParticipant(self, participantOrdinal):
        self.recoPartOrdinal.append(participantOrdinal)

    def computeLagrangeCoeffs(self):
        # Define proper dimensions
        t = self.nParticipants - self.tolerance
        rows = t
        cols = self.l
        # Initialize Lagrange's coeffs
        lagrangeCoeffs = [[0] * cols for _ in range(rows)]
        
        for j in range(cols):
            for i in range(rows):
                num = 1
                den = 1
                for m in range(t):
                    if m != i:
                        tmp = (-j - self.recoPartOrdinal[m]) % self.sizeDomain
                        num = (num * tmp) % self.sizeDomain
                        tmp = (self.recoPartOrdinal[i] - self.recoPartOrdinal[m]) % self.sizeDomain
                        den = (den * tmp) % self.sizeDomain
                invden = pow(den, -1, self.sizeDomain)
                mu = (num * invden) % self.sizeDomain
                lagrangeCoeffs[i][j] = mu

        return lagrangeCoeffs
    
    def calculateSecrets(self):

        global hS
        hS = []

        if(len(self.decryptedShares) == self.nParticipants):
            for i in self.decryptedShares:
                hS.append(pow(self.generator, i, self.order))
        else:
            hS = self.reconstructionOfSecrets()

        return hS    

    def reconstructionOfSecrets(self):

        lagrange = self.computeLagrangeCoeffs()

        S = [] * self.l

        for j in range(self.l):
            S[self.l - j - 1] = 1
            for i in range(self.tolerance):
                lagr = lagrange[i][j]
                tmp = pow(self.decryptedShares[i],lagr, self.sizeDomain)
                S[self.l - j - 1] = (S[self.l - j - 1] * tmp) % self.sizeDomain

        return S        

    def generateVandermondeMatrix(self):
        
        self.vandermonde = []

        for i in range(self.l):
            row = []
            for j in range(self.l + self.tolerance):
                tmp = pow(self.w, i * j, self.order)
                if tmp == 0:
                    tmp = 1
                row.append(tmp)    
            self.vandermonde.append(row)
        
        return self.vandermonde
    

    def generateResultMatrix(self):

        resultMatrix = []

        for i in range(len(self.vandermonde)):
            temp = self.vandermonde[i] * hS
            resultMatrix.append(temp)

        return resultMatrix