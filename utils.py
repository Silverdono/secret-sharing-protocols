from random import randint
from ldei import LDEI
from dleq import DLEQ
from ecpy.curves import Point

# Generate random key winthin order cyclic group
def generateKeys(h: int, q: int, p : int):
    privateKey = randint(1, int(q)-1) #Range starts at 1 because 0 is not a valid public key
    publicKey = pow(h, privateKey, p)
    return publicKey, privateKey

# Finding a valid generator for a given cyclic group, only works when q is prime, but in this program always will be
# Used algorithm found in https://github.com/evapln/albatross/blob/master/CyclicGroup/src/func.cpp
# Generator should comply with gen**2 mod q != 1 and gen**q mod q != 1
def findGenerator(q : int):
    for i in range(2, 2*q + 1):
        temp = pow(i, 2, q)
        if temp == 1:
            continue
        temp = pow(i, q, q)
        if temp == 1:
            continue
        return i # Return i if previous conditions fulfilled
    return -1 # Return -1 if no generator found

# Find multiplicative order of generator h inside Cyclic Group of p size
def findMultiplicativeOrder(h: int, p: int):
    i = 1
    while pow(h,i,p) != 1:
        i += 1
    return i    

# Generate random polynomial inside cyclic group of order q
def generatePolynomial(t : int, l : int, q : int): 
    coefs = [randint(0, q-1) for _ in range(int(t + l + 1))]
    return coefs

# Compute polynomial for all n participants inside cyclic group
# Return plain computed shares and cyphered ones with public key
def computePolynomial(coefs, pks, l:int, n, q, p):

    #Implementacion de πPPVSS del documento (fichas.pdf, pag. 15) 

    shares = [-1] * int(n)
    encryptedShares = [-1] * int(n)
   
    for i in range(1, n+1):
        shares[i-1] = evalPoly(coefs, i) % q
        encryptedShares[i-1] = int(pow(pks[i-1], shares[i-1]) % p)

    return shares, encryptedShares

# Compute shares and encryptedShares for elliptic curve
def computePolynomialEC(coefs, EPKs : list[Point], n, q):

    shares = [-1] * int(n)
    encryptedShares : list[Point] = [-1] * int(n)

    for i in range(1, n+1):
        shares[i-1] = evalPoly(coefs, i) % q
        encryptedShares[i-1] = EPKs[i-1].mul(shares[i-1])

    return shares, encryptedShares

# Eval poly using Horner
def evalPoly(coefs, x):
    y = 0
    for a in coefs:
        y = y * x + a
    return y



# Generate LDEI proof for a computed polynomial using a list of his coefficients
def generateLDEI(poly, encryptedShares, pk : list[int], n, q, p, t, l):

    auxPolynomial = generatePolynomial(t, l, q) # Generating random polynomial of degree t+l+1

    return generateLDEI_NonRandom(poly, encryptedShares, pk, n, q, p, auxPolynomial)


# Abstract LDEI generation logic of the random polynomial to be able to test it with a defined one
def generateLDEI_NonRandom(poly, encryptedShares, pk : list[int], n, q, p, auxPolynomial):

    auxComputedPoly = [-1] * n

    for i in range(1, n+1):
        auxComputedPoly[i-1] = evalPoly(auxPolynomial, i) % q   

    a = [-1] * len(auxComputedPoly)
    for i in range(0, n):
        a[i] = pow(pk[i], auxComputedPoly[i], p)

    # Literature about this process calculates e as the hash of the auxiliar polynomial
    # We use "custom" hash function because lists are not hashable    
    e = (sum((a[i-1] * i * encryptedShares[i-1]) for i in range(1, n+1))) % q

    temp = [-1] * len(poly)
    # Multiply poly with e
    for i in range(len(poly)):
        temp[i] = (poly[i] * e) % q

    z = [(a + b)%q for a, b in zip(temp, auxPolynomial)]

    return a,e,z

#  Generate LDEI proof for a computed polynomial using a list of his coefficients in case coef[i] = 0 for elliptic curves
def generateLDEI_EC(poly, encryptedShares: list[Point], pk : list[Point], n, q, t, l):

    auxPolynomial = generatePolynomial(t, l, q)
    return generateLDEI_EC_NonRandom(poly, encryptedShares, pk, n, q, auxPolynomial)

# Abstract LDEI generation logic of the random polynomial to be able to test it with a defined one
def generateLDEI_EC_NonRandom(poly:list[int], encryptedShares: list[Point], pk : list[Point], n, q, auxPolynomial: list[int]):

    auxComputedPoly : list[int] = [-1] * n
    for i in range(1, n+1):
        auxComputedPoly[i-1] = evalPoly(auxPolynomial, i) % q

    a : list[Point] = [-1] * len(auxComputedPoly)
    for i in range(0,n):
        a[i] = auxComputedPoly[i] * pk[i]

    e = (sum((a[i-1].x * i * encryptedShares[i-1].x) for i in range(1, n+1))) % q

    temp = [(coef * e) % q for coef in poly]
    z = [(a + b)%q for a, b in zip(temp, auxPolynomial)]

    return a,e,z



def verifyLDEI(ldei: LDEI, pk: list[int], shares: list[int], n, k, q, p):

    if(len(pk) != len(ldei.a) or len(shares) != len(ldei.a)):
        print("LDEI no valido")
        return False
    if(len(ldei.z) - 1 > k):
        print("LDEI no valido")
        return False

    auxE = (sum((ldei.a[i-1] * i * shares[i-1]) for i in range(1, n+1))) % q

    if(auxE != ldei.e):
        print("LDEI no valido")
        return False

    auxZeval = [-1] * n

    for i in range(1, n+1):
        auxZeval[i-1] = evalPoly(ldei.z,i) % q

    for i in range(n):
        temp1 = pow(pk[i], auxZeval[i], p)
        temp2 = pow(shares[i], auxE, p)
        temp3 = (temp2 * ldei.a[i]) % p
        if(temp3 != temp1):
            print("LDEI no valido", i)
            return False
        
    return True

def verifyLDEI_EC(ldei: LDEI, pk: list[Point], shares: list[Point], n, k, q):

    if(len(pk) != len(ldei.a) or len(shares) != len(ldei.a)):
        print("LDEI no valido")
        return False
    
    if(len(ldei.z) - 1 > k):
        print("LDEI no valido")
        return False

    auxE = (sum(((ldei.a[i-1]).x * i * (shares[i-1]).x) for i in range(1, n+1))) % q

    if(auxE != ldei.e):
        print("LDEI no valido")
        return False

    auxZeval : list[int] = [-1] * n

    for i in range(1, n+1):
        auxZeval[i-1] = evalPoly(ldei.z,i) % q

    for i in range(n):
        temp1 = int(auxZeval[i]) * pk[i]
        temp2 = int(ldei.e) * shares[i]
        temp3 = temp2 + ldei.a[i]

        if(temp3 != temp1):
            print("LDEI no valido", i)
            return False

    return True


def verifyDLEQ(dleq : DLEQ, encryptedShares, dleqShares, q, p):

    auxE = (sum((dleq.a[i] * dleqShares[i] * encryptedShares[i]) for i in range(0, len(dleq.a)))) % q

    if auxE != dleq.e:
        return False
    
    for i in range(len(dleq.a)):
        temp1 = (pow(encryptedShares[i], dleq.z)) % p
        temp2 = (pow(dleqShares[i], dleq.e)) % p
        temp3 = (temp1 * temp2) % p
        if dleq.a[i] != temp3:
            return False
        
    return True

def computeLagrangeCoeffs(n, tolerance, l, q, plainShares):
    # Define proper dimensions
    t = n - tolerance
    rows = t
    cols = l
    # Initialize Lagrange's coeffs
    lagrangeCoeffs = [[0] * cols for _ in range(rows)]
        
    for j in range(cols):
        for i in range(rows):
            num = 1
            den = 1
            for m in range(t):
                if m != i:
                    tmp = (-j - plainShares[m]) % q
                    num = (num * tmp) % q
                    tmp = (plainShares[i] - plainShares[m]) % q
                    den = (den * tmp) % q
            invden = pow(den, -1, q)
            mu = (num * invden) % q
            lagrangeCoeffs[i][j] = mu

    return lagrangeCoeffs

def calculateSecrets(n, t, l, h : int | Point, p, plainShares, EC_Flag : bool):

    hS = []

    if(len(plainShares) == n):
        for i in plainShares:
            if(EC_Flag):
                hS.append(h * i)
            else:    
                hS.append(pow(h, i, p))
    else:
        hS = reconstructionOfSecrets(n, t, l, p, plainShares)
    return hS   

def reconstructionOfSecrets(n, t, l, p, plainShares):

    lagrange = computeLagrangeCoeffs(n, t, l, p, plainShares)

    S = [] * l

    for j in range(l):
        S[l - j - 1] = 1
        for i in range(t):
            lagr = lagrange[i][j]
            tmp = pow(plainShares[i],lagr, p)
            S[l - j - 1] = (S[l - j - 1] * tmp) % p

    return S    

def generateVandermondeMatrix(t, l, w, order):
        
        vandermonde = []

        for i in range(l):
            row = []
            for j in range(l + t):
                tmp = pow(w, i * j, order)
                if tmp == 0:
                    tmp = 1
                row.append(tmp)    
            vandermonde.append(row)
        
        return vandermonde

def generateResultMatrix(vandermonde, shares):

    auxShares = transposeMatrix(shares)

    return mulMatrix(vandermonde, auxShares)

def transposeMatrix(matrix):
    rows = len(matrix)
    cols = len(matrix[0])

    T = []
    for j in range(cols):
        row = []
        for i in range(rows):
            row.append(matrix[i][j])
        T.append(row)

    return T

def mulMatrix(matrix1, matrix2):

    row1 = len(matrix1)
    cols1 = len(matrix1[0])

    row2 = len(matrix2)
    cols2 = len(matrix2[0])

    result = []
    for _ in range(row1):
        result.append([0] * cols2)

    for i in range(row1):
        for k in range(cols1):
            auxValue = matrix1[i][k]
            for j in range(cols2):
                result[i][j] += auxValue * matrix2[k][j]

    return result