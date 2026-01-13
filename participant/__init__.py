from flask import Flask, request, jsonify, session
from ecpy.curves import Curve, Point
from ecpy.keys import ECPrivateKey, ECPublicKey
from random import getrandbits, randint
import utils
import requests


ordinal = -1



def create_app(nOrdinal):
    global ordinal
    ordinal = nOrdinal
    app = Flask("Participant " + str(ordinal))

    import secrets as sessionSecret
    app.secret_key = sessionSecret.token_hex()

    goodParticipant : bool = not not getrandbits(1) # Negating twice the random bit is faster than cast a bool

    #Cyclic group
    @app.route('/setup_variables', methods = ["POST"])
    def setupVariables():
        bodyContent = request.json
        session['n'] = bodyContent['n']
        session['t'] = bodyContent['t']
        session['p'] = bodyContent['p']
        session['q'] = bodyContent['q']
        session['h'] = bodyContent['h']
        session['l'] = bodyContent['l']
        return "Variables saved"

    @app.get("/get_public_key")
    def sendPublickKey():
        if(validateContext()):
            p : int = session.get('p')
            q : int = session.get('q')
            h : int = session.get('h')
            if('publicKey' not in session):
                pk, sk = utils.generateKeys(h, q, p)
                session['publicKey'] = pk
                session['secretKey'] = sk
                return jsonify({'pk' : pk})
            else:
                return jsonify({'pk' : session.get('publicKey')})
        else:
            return "Non valid context"    

    @app.get("/get_encrypted_shares")
    def sendEncryptedShares():
        if(validateContext() and ('publicKey' in session)):
            t = session.get('t')
            l = session.get('l')
            q = session.get('q')
            p = session.get('p')
            publicKey = session.get('publicKey')
            n = session.get('n')
            h = session.get('h')
            if('polynomial' not in session):
                session['polynomial'] = utils.generatePolynomial(t, l, q)
            if('shares' not in session):
                shares, encryptedShares = utils.computePolynomial(session.get('polynomial'), publicKey, l, n, q, p)
                session['shares'] = shares
                session['encryptedShares'] = encryptedShares

                return jsonify({'eS' : encryptedShares})
            else:
                return jsonify({'eS' : session.get('encryptedShares')})
        else:
            return "Non valid context"        

    @app.post("/get_ldei")
    def sendLDEI():
        if(validateContext() 
           and ('publicKey' in session) 
           and ('polynomial' in session)
           and ('encryptedShares' in session)):
            bodyContent = request.json
            allPublicKeys = bodyContent['pks']
            t = session.get('t')
            l = session.get('l')
            q = session.get('q')
            p = session.get('p')
            n = session.get('n')
            polynomial = session.get('polynomial')
            encryptedShares = session.get('encryptedShares')
            if('computedLDEI' not in session):
                auxA, auxE, auxZ = utils.generateLDEI(polynomial, encryptedShares, allPublicKeys, n, q, p, t, l)
                computedLDEI = {'a' : auxA, 'e': auxE, 'z' : auxZ}
                session['computedLDEI'] = computedLDEI

                return jsonify({'a' : auxA, 'e': auxE, 'z' : auxZ})
            else:
                computedLDEI = session.get('computedLDEI')
                return jsonify({'a' : computedLDEI['a'], 'e': computedLDEI['e'], 'z' : computedLDEI['z']})
        else:
            return "Non valid context"        

    @app.get("/post_shares")
    def postShares():
        if(validateContext()
           and ('shares' in session)):
            # if(goodParticipant):    
            shares = session.get('shares')
            requests.post("http://localhost:6000/post_shares", None, {'shares': shares}) # Post shares to ledger
        else:
            return "Non valid context"    
        

    #Elliptic curve
    @app.route('/setup_variables_ec', methods = ["POST"])
    def setupVariablesEC():
        bodyContent = request.json
        session['n'] = bodyContent['n']
        session['t'] = bodyContent['t']

        curveName : str = bodyContent['ec_name']
        session['ec_name'] = curveName
        curve = Curve.get_curve(curveName)
        session['ec'] = curve
        session['q'] = curve._domain["order"]

        session['l'] = bodyContent['l']
        return "Variables saved"    
    
    @app.get("/get_public_key_ec")
    def sendPublickKeyEC():
        if(validateContextEC()):
            q : int = session.get('q')
            ec : Curve = session.get('ec')
            if('publicKey' not in session):
                scalar = randint(1, int(q)-1)
                sk = ECPrivateKey(scalar, ec)
                pk = sk.get_public_key()
                session['scalar'] = scalar
                session['publicKey'] = pk
                session['secretKey'] = sk
                return jsonify({'pk' : pk})
            else:
                return jsonify({'pk' : session.get('publicKey')})
        else:
            return "Non valid context"   
        
    @app.get("/get_encrypted_shares_ec")
    def sendEncryptedSharesEC():
        if(validateContextEC() and ('publicKey' in session)):
            t = session.get('t')
            l = session.get('l')
            q = session.get('q')
            publicKey : ECPublicKey = session.get('publicKey')
            n = session.get('n')
            if('polynomial' not in session):
                session['polynomial'] = utils.generatePolynomial(t, l, q)
            if('shares' not in session):
                shares, encryptedShares = utils.computePolynomialEC(session.get('polynomial'), publicKey.W, n, q)
                session['shares'] = shares
                session['encryptedShares'] = encryptedShares

                return jsonify({'eS' : encryptedShares})
            else:
                return jsonify({'eS' : session.get('encryptedShares')})
        else:
            return "Non valid context"         
        

    @app.post("/get_ldei_ec")
    def sendLDEI_EC():
        if(validateContextEC() 
           and ('publicKey' in session) 
           and ('polynomial' in session)
           and ('encryptedShares' in session)):
            bodyContent = request.json
            allPublicKeys = bodyContent['pks']
            t = session.get('t')
            l = session.get('l')
            q = session.get('q')
            n = session.get('n')
            polynomial = session.get('polynomial')
            encryptedShares = session.get('encryptedShares')
            if('computedLDEI' not in session):
                auxA, auxE, auxZ = utils.generateLDEI_EC(polynomial, encryptedShares, allPublicKeys, n, q, t, l)
                computedLDEI = {'a' : auxA, 'e': auxE, 'z' : auxZ}
                session['computedLDEI'] = computedLDEI

                return jsonify({'a' : auxA, 'e': auxE, 'z' : auxZ})
            else:
                computedLDEI = session.get('computedLDEI')
                return jsonify({'a' : computedLDEI['a'], 'e': computedLDEI['e'], 'z' : computedLDEI['z']})
        else:
            return "Non valid context"            

    def validateContext():
        if(session.get('n') == -1 
        or session.get('t') == -1
        or session.get('p') == -1
        or session.get('q') == -1
        or session.get('h') == -1
        or session.get('l') == -1
        ):
            return False
        else:
            return True
        
    def validateContextEC():
        if(session.get('n') == -1 
        or session.get('t') == -1
        or session.get('p') == -1
        or session.get('q') == -1
        or session.get('ec') == None
        or session.get('l') == -1
        ):
            return False
        else:
            return True    

    return app