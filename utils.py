from random import randint
from ldei import LDEI
from dleq import DLEQ

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

# Generate random polynom inside cyclic group of order q
def generatePolynom(t : int, l : int, q : int): 
    coefs = [randint(0, q) for _ in range(int(t + l))]
    # poly = Poly(coefs, X)
    # poly.set_modulus(q)
    return coefs

# Compute polynom for all n participants inside cyclic group
# Return plain computed shares and cyphered ones with public key
def computePolynom(coefs, pk, l:int, n, q, p, h):

    #Implementacion de πPPVSS del documento (fichas.pdf, pag. 15) 

    secrets = [-1] * int(l)
    encryptedSecrets = [-1] * int(l)

    for i in range(0, int(l)):
        secrets[i] = evalPoly(coefs, i) % q
        encryptedSecrets[i] = pow(h, secrets[i]) % p

    shares = [-1] * int(n)
    encryptedShares = [-1] * int(n)
    for i in range(1, n+1):
        shares[i-1] = evalPoly(coefs, i) % q
        encryptedShares[i-1] = int(pow(pk, shares[i-1]) % p)

    return secrets, encryptedSecrets, shares, encryptedShares

# Eval poly using Horner
def evalPoly(coefs, x):
    y = 0
    for a in coefs:
        y = y * x + a
    return y



# Generate LDEI proof for a computed polynom using a list of his coefficients in case coef[i] = 0
# TODO: consultar esto, no queda claro si se hace con todas las claves publicas o solo con la propia
def generateLDEI(poly, encryptedShares, pk, n, q, t, l) -> LDEI:

    auxPolynom = generatePolynom(t+1, l, q) # Generating random polynom of degree t+l+1
    auxComputedPoly = [-1] * n
    for i in range(1, n+1):
        auxComputedPoly[i-1] = evalPoly(auxPolynom, i) % q

    a = [-1] * len(auxComputedPoly)
    for i in range(0, n):
        a[i] = pow(pk, auxComputedPoly[i]) % q

    # Literature about this process calculates e as the hash of the auxiliar polynom
    # We use "custom" hash function because lists are not hashable    
    e = (sum((a[i-1] * i * encryptedShares[i-1]) for i in range(1, n+1))) % q


    temp = [-1] * len(poly)
    # Multiply poly with e
    for i in range(len(poly)):
        temp[i] = poly[i] * e % q

    z = [(a + b)%q for a, b in zip(temp, auxPolynom)]

    # return LDEI(a, e, z)
    return a,e,z



def verifyLDEI(ldei: LDEI, publicKey, shares, n, q):

    auxE = (sum((ldei.a[i-1] * i * shares[i-1]) for i in range(1, n+1))) % q

    auxZeval = [-1] * n

    for i in range(1, n+1):
        auxZeval[i-1] = ldei.z.eval(X, i) % q

    for i in range(n):
        temp1 = pow(publicKey, auxZeval[i]) % q
        temp2 = pow(shares[i], auxE) % q
        temp3 = (temp2 * ldei.a[i]) % q
        if(temp3 != temp1):
            print("LDEI no valido", i)
            break


def verifyDLEQ(dleq : DLEQ, encryptedShares, dleqShares, q):

    auxE = (sum((dleq.a[i] * dleqShares[i] * encryptedShares[i]) for i in range(0, len(dleq.a)))) % q

    if auxE != dleq.e:
        return False
    
    for i in range(len(dleq.a)):
        temp1 = (pow(encryptedShares[i], dleq.z)) % q
        temp2 = (pow(dleqShares[i], dleq.e)) % q
        temp3 = (temp1 * temp2) % q
        if dleq.a[i] != temp3:
            return False
        
    return True
