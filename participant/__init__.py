import logging
from flask import Flask, request, jsonify
from ecpy.curves import Curve, Point
from ecpy.keys import ECPrivateKey, ECPublicKey
from random import getrandbits, randint
import utils
import json
import time


def create_app(nOrdinal, debug_mode : bool):
    global ordinal
    ordinal = nOrdinal
    app = Flask("Participant " + str(ordinal))

    global debugMode
    debugMode = debug_mode


    import secrets as sessionSecret
    app.secret_key = sessionSecret.token_hex()

    logging.getLogger("werkzeug").setLevel(logging.WARNING) # Remove verbosity in stdout from useless logs

    goodParticipant : bool = not not getrandbits(1) # Negating twice the random bit is faster than cast a bool

    # Variable declaration for all workflows
    n : int
    t : int
    p : int
    q : int
    h : int
    l : int
    ec : Curve
    ecName : str

    #Cyclic group variables
    global pk_cg
    pk_cg = None
    global sk_cg
    sk_cg = None
    global encrypt_shares_cg
    encrypt_shares_cg = None
    global computedLDEI_cg
    computedLDEI_cg = None

    #Elliptic curve 
    global pk_ec
    pk_ec = None
    global sk_ec
    sk_ec = None
    global encrypt_shares_ec
    encrypt_shares_ec = None
    global computedLDEI_ec
    computedLDEI_ec = None


    global plainShares
    plainShares = None
    global polynomial
    polynomial = None

    #Cyclic group
    @app.route('/setup_variables', methods = ["POST"])
    def setupVariables():
        start_time = time.time()
        bodyContent = request.json
        global n
        n = bodyContent['n']
        global t
        t = bodyContent['t']
        global p
        p = bodyContent['p']
        global q
        q = bodyContent['q']
        global h
        h = bodyContent['h']
        global l
        l = bodyContent['l']

        end_time = time.time()
        global ordinal
        global debugMode
        if(debugMode):
            print("Setup variables {", ordinal,"}: ", end_time-start_time)
        return "Variables saved"

    @app.get("/get_public_key")
    def sendPublickKey():
        if(validateContext()):
            start_time = time.time()

            global p
            global q
            global h
            global pk_cg
            if(pk_cg == None):
                pk, sk = utils.generateKeys(h, q, p)
                pk_cg = pk
                global sk_cg
                sk_cg = sk

            end_time = time.time()
            global ordinal
            global debugMode
            if(debugMode):
                print("Generating keys {", ordinal,"}: ", end_time-start_time)
            return jsonify({'pk' : pk_cg})
        else:
            return "Non valid context", 400    

    @app.post("/get_encrypted_shares")
    def sendEncryptedShares():
        global pk_cg
        if(validateContext() and (pk_cg != None)):

            start_time = time.time()

            global n
            global t
            global p
            global q
            global h
            global l
            global polynomial
            global plainShares
            global encrypt_shares_cg

            bodyContent = request.json
            allPublicKeysBody = json.loads(bodyContent['pks'])

            allPublicKeys = [int(pk) for pk in allPublicKeysBody]
            
            if(polynomial == None):
                polynomial = utils.generatePolynomial(t, l, q)
            if(plainShares == None):
                shares, encryptedShares = utils.computePolynomial(polynomial, allPublicKeys, l, n, q, p)
                plainShares = shares
                encrypt_shares_cg = encryptedShares


            end_time = time.time()
            global ordinal
            global debugMode
            if(debugMode):
               print("Computing shares {", ordinal,"}: ", end_time-start_time)

            return jsonify({'eS' : encrypt_shares_cg})
        else:
            return "Non valid context", 400        

    @app.post("/get_ldei")
    def sendLDEI():
        global pk_cg
        global polynomial
        global encrypt_shares_cg
        if(validateContext() 
           and (pk_cg != None) 
           and (polynomial != None)
           and (encrypt_shares_cg != None)):
            
            start_time = time.time()

            bodyContent = request.json
            allPublicKeysBody = json.loads(bodyContent['pks'])

            allPublicKeys = [int(pk) for pk in allPublicKeysBody]

            global t
            global l
            global q
            global p
            global n

            global computedLDEI_cg

            if(computedLDEI_cg == None):
                auxA, auxE, auxZ = utils.generateLDEI(polynomial, encrypt_shares_cg, allPublicKeys, n, q, p, t, l)
                computedLDEI = {'a' : auxA, 'e': auxE, 'z' : auxZ}
                computedLDEI_cg = computedLDEI

            end_time = time.time()
            global ordinal
            global debugMode
            if(debugMode):
                print("Computing LDEI {", ordinal,"}: ", end_time-start_time)

            return jsonify({'a' : computedLDEI_cg['a'], 'e': computedLDEI_cg['e'], 'z' : computedLDEI_cg['z']})
        else:
            return "Non valid context", 400        
 

    #Elliptic curve
    @app.route('/setup_variables_ec', methods = ["POST"])
    def setupVariablesEC():

        start_time = time.time()

        bodyContent = request.json
        global n
        n = bodyContent['n']
        global t
        t = bodyContent['t']

        curveName : str = bodyContent['ec_name']
        global ecName
        ecName = curveName
        global ec
        ec = Curve.get_curve(curveName)
        global q
        q = ec._domain["order"]

        global l
        l = bodyContent['l']

        end_time = time.time()
        global ordinal
        global debugMode
        if(debugMode):
            print("Setup variables {", ordinal,"}: ", end_time-start_time)

        return "Variables saved"    
    
    @app.get("/get_public_key_ec")
    def sendPublickKeyEC():
        if(validateContextEC()):

            start_time = time.time()

            global q
            global ec
            global pk_ec
            global sk_ec
            global ec
            if(pk_ec == None):
                scalar = randint(1, int(q)-1)
                sk = ECPrivateKey(scalar, ec)
                pk = sk.get_public_key()
                pk_ec = pk
                sk_ec = sk

            end_time = time.time()
            global ordinal
            global debugMode
            if(debugMode):
               print("Generating keys {", ordinal,"}: ", end_time-start_time)

            encodedPk = ec.encode_point(pk_ec.W)
            return jsonify({'pk' : encodedPk})
        else:
            return "Non valid context", 400   
        
    @app.post("/get_encrypted_shares_ec")
    def sendEncryptedSharesEC():
        global pk_ec
        if(validateContextEC() and (pk_ec != None)):

            start_time = time.time()

            global t
            global l
            global q
            global n

            bodyContent = request.json
            allPublicKeysBody = bodyContent['pks']

            global ec
            allPublicKeys = [ec.decode_point(p) for p in allPublicKeysBody]
            
            global polynomial
            if(polynomial == None):
                polynomial = utils.generatePolynomial(t, l, q)

            global plainShares
            global encrypt_shares_ec    

            global ec
            if(plainShares == None):
                shares, encryptedShares = utils.computePolynomialEC(polynomial, allPublicKeys, n, q)
                plainShares = shares
                encrypt_shares_ec = encryptedShares


            encodedShares = [ec.encode_point(p) for p in encrypt_shares_ec]

            end_time = time.time()
            global ordinal
            global debugMode
            if(debugMode):
               print("Computing shares {", ordinal,"}: ", end_time-start_time)

            return jsonify({'eS' : encodedShares})
        else:
            return "Non valid context", 400         
        

    @app.post("/get_ldei_ec")
    def sendLDEI_EC():
        global pk_ec
        global polynomial
        global encrypt_shares_ec

        if(validateContextEC() 
           and (pk_ec != None) 
           and (polynomial != None)
           and (encrypt_shares_ec != None)):
            
            start_time = time.time()

            bodyContent = request.json
            allPublicKeysBody = bodyContent['pks']

            global ec
            allPublicKeys = [ec.decode_point(p) for p in allPublicKeysBody]

            global t
            global l
            global q
            global n

            global computedLDEI_ec
            global ec
            if(computedLDEI_ec == None):
                auxA, auxE, auxZ = utils.generateLDEI_EC(polynomial, encrypt_shares_ec, allPublicKeys, n, q, t, l)
                computedLDEI = {'a' : auxA, 'e': auxE, 'z' : auxZ}
                computedLDEI_ec = computedLDEI

            end_time = time.time()
            global ordinal
            global debugMode
            if(debugMode):
                print("Computing LDEI {", ordinal,"}: ", end_time-start_time)

            encodedLDEI_A = [ec.encode_point(a) for a in computedLDEI_ec['a']]
            return jsonify({'a' : encodedLDEI_A, 'e': computedLDEI_ec['e'], 'z' : computedLDEI_ec['z']})
        else:
            return "Non valid context", 400            

    @app.get("/post_shares")
    def postShares():
        global plainShares
        if(plainShares != None):
            # if(goodParticipant):    
            return jsonify({'shares': plainShares}) # Post shares to ledger
        else:
            return "Non valid context", 400    

    def validateContext():
        global n
        global t
        global p
        global q
        global h
        global l

        if(n == None 
        or t == None
        or p == None
        or q == None
        or h == None
        or l == None
        ):
            return False
        else:
            return True
        
    def validateContextEC():
        global n
        global t
        global q
        global ec
        global l
        if(n == None
        or t == None
        or q == None
        or ec == None
        or l == None
        ):
            return False
        else:
            return True    

    return app