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
    
def calculateSecrets(n, t, l, h, q, plainShares):

    hS = []

    if(len(plainShares) == n):
        for i in plainShares:
            hS.append(pow(h, i, q))
    else:
        hS = reconstructionOfSecrets(n, t, l, q, plainShares)

    return hS    

def reconstructionOfSecrets(n, t, l, q, plainShares):

    lagrange = computeLagrangeCoeffs(n, t, l, q, plainShares)

    S = [] * l

    for j in range(l):
        S[l - j - 1] = 1
        for i in range(t):
            lagr = lagrange[i][j]
            tmp = pow(plainShares[i],lagr, q)
            S[l - j - 1] = (S[l - j - 1] * tmp) % q

    return S        

def generateVandermondeMatrix(l, t, w, q):
        
    vandermonde = []

    for i in range(l):
        row = []
        for j in range(l + t):
            tmp = pow(w, i * j, q)
            if tmp == 0:
                tmp = 1
            row.append(tmp)    
        vandermonde.append(row)
        
    return vandermonde
    

def generateResultMatrix(l, t, w, q, h, hS):

    vandermonde = generateVandermondeMatrix(l, t, w, q)

    resultMatrix = []

    for i in range(l):
        row = []
        for j in range(l + t):
            temp = vandermonde[i][j] * hS[j]
            result = pow(h,temp)
            row.append(result)
        resultMatrix.append(row)

    return resultMatrix