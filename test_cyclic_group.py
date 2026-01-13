import utils
from ldei import LDEI
from parts import Part
from random import randint

if __name__ == "__main__":
    n = 11
    t = int(n/3)
    p = 523
    gen = utils.findGenerator(p)
    q = utils.findMultiplicativeOrder(gen, p)
    l = int(n - 2 * t)

    pk = 300
    pks = [pk] * int(n)

    # Test compute polynomial
    polynomial : list[int] = [206, 32, 84, 234, 400, 58, 471, 491]
    result_polynomial : list[int] = [-1] * int(l)
    for i in range(0,int(l)):
        result_polynomial[i] = utils.evalPoly(polynomial, i) % q

    assert(result_polynomial == [491, 410, 41, 266, 377])

    # Test generation of shares

    shares, encryptedShares = utils.computePolynomial(polynomial, pk, l, n, q, p)

    assert(encryptedShares == [168, 330, 253, 113, 31, 236, 301, 352, 425, 433, 294])

    # Test generation LDEI

    auxPolynomial : list[int] = [63, 249, 412, 459, 80, 34, 162, 497]

    a,e,z = utils.generateLDEI_NonRandom(polynomial, encryptedShares, pks, n, q, p, auxPolynomial)
    ldei = LDEI(a,e,z)

    resultLDEI = LDEI([289, 129, 381, 370, 280, 429, 134, 219, 292, 239, 345],119,[43, 403, 490, 117, 178, 150, 357, 462])

    assert(ldei == resultLDEI)

    # Test validation LDEI

    assert(utils.verifyLDEI(ldei, pks, encryptedShares, n, t+l, q, p))

    # Test result matrix generation

    finalShares = []
    for i in range(n):
        part = Part(i,t,l,n,q,p,gen, "", False)
        finalShares.append(part.sendShares()[1])

    w = 171
    vandermonde = utils.generateVandermondeMatrix(t,l,w,q)
    resultMatrix = utils.generateResultMatrix(vandermonde, finalShares)    

    assert(resultMatrix != None)

    print("ALBATROSS with Cyclic Groups test finished sucessfully!")
