import utils
from ldei import LDEI
from parts import Part

if __name__ == "__main__":
    n = 11
    t = int(n/3)
    p = 523
    gen = utils.findGenerator(p)
    q = utils.findMultiplicativeOrder(gen, p)
    l = int(n - 2 * t)

    pks = [106, 402, 51, 118, 27, 24, 186, 408, 282, 90, 10]    

    # Test compute polynomial
    polynomial : list[int] = [219, 306, 230, 176, 208, 170, 291, 146, 328]

    result_polynomial : list[int] = [-1] * int(l)
    for i in range(0,int(l)):
        result_polynomial[i] = utils.evalPoly(polynomial, i) % q

    assert(result_polynomial == [328, 508, 430, 172, 484])

    # Test generation of shares

    shares, encryptedShares = utils.computePolynomial(polynomial, pks, l, n, q, p)

    assert(encryptedShares == [230, 73, 112, 356, 304, 78, 343, 280, 68, 381, 261])

    # Test generation LDEI

    auxPolynomial : list[int] = [441, 214, 140, 231, 324, 220, 457, 402, 94]

    a,e,z = utils.generateLDEI_NonRandom(polynomial, encryptedShares, pks, n, q, p, auxPolynomial)
    ldei = LDEI(a,e,z)

    resultLDEI = LDEI([61, 73, 370, 435, 95, 289, 280, 174, 204, 472, 49],75,[162, 196, 164, 381, 264, 442, 358, 390, 160])

    assert(ldei == resultLDEI)

    # Test validation LDEI

    assert(utils.verifyLDEI(ldei, pks, encryptedShares, n, t+l, q, p))

    # Test result matrix generation

    finalShares = []
    for i in range(n):
        part = Part(i,t,l,n,q,p,gen, "", False)
        part.generateShares(pks)
        finalShares.append(part.sendShares()[1])

    w = 171
    vandermonde = utils.generateVandermondeMatrix(t,l,w,q)
    resultMatrix = utils.generateResultMatrix(vandermonde, finalShares)    

    assert(resultMatrix != None)

    print("ALBATROSS with Cyclic Groups test finished sucessfully!")
