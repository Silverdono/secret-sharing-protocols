from flask import Flask, request, session
from random import randint
from ecpy.curves import Curve
import requests
import json
import utils
from . import functions
from ldei import LDEI


def create_app(n, p, elliptic : bool):

    app = Flask("Public ledger")

    import secrets as sessionSecret
    app.secret_key = sessionSecret.token_hex()

    h = utils.findGenerator(p) # Generator
    q = utils.findMultiplicativeOrder(h,p) # Multiplicative order of h in p

    t = int(n/3) # Tolerance -- A bit arbitrary this value
    l = int(n - 2 * t) # l

    w = randint(0, q) # Base used for vandermonde matrix smaller than multiplicative order of q

    publicKeys = [-1] * n # Participants' public keys
    encryptedShares = [-1] * n # Participants' encrypted shares
    ldeis = [-1] * n # Participants' computed LDEIs

    EC : Curve

    # Send data to participants

    url = "http://localhost:50"

    if(not elliptic):
        jsonBody = {
            'n' : n,
            'q' : q,
            'p' : p,
            'h' : h,
            't' : t,
            'l' : l
        }

        for i in range (n):
            tmpUrl = url
            if(i/10 < 1):
                tmpUrl += "0" + str(i) + "/setup_variables"
            else:
                tmpUrl += str(i) + "/setup_variables"

            requests.post(tmpUrl, None, jsonBody)


        # Request public keys

        for i in range (n):
            tmpUrl = url
            if(i/10 < 1):
                tmpUrl += "0" + str(i) + "/get_public_key"
            else:
                tmpUrl += str(i) + "/get_public_key"

            response = requests.get(tmpUrl)
            print(response)
            publicKeys[i] = json.load(response)['pk']


        # Request encrypted shares

        for i in range (n):
            tmpUrl = url
            if(i/10 < 1):
                tmpUrl += "0" + str(i) + "/get_encrypted_shares"
            else:
                tmpUrl += str(i) + "/get_encrypted_shares"

            response = requests.get(tmpUrl).json()
            encryptedShares[i] = json.load(response)['eS']

        # Request computed LDEIs

        for i in range (n):
            tmpUrl = url
            if(i/10 < 1):
                tmpUrl += "0" + str(i) + "/get_ldei"
            else:
                tmpUrl += str(i) + "/get_ldei"

            response = requests.get(tmpUrl).json()
            responseJson = json.load(response)
            tmpA = responseJson['a']
            tmpE = responseJson['e']
            tmpZ = responseJson['z']
            ldeis[i] = LDEI(tmpA, tmpE, tmpZ)
    else:

        curveName : str = 'secp256k1'
        EC = Curve.get_curve(curveName)

        jsonBody = {
            'n' : n,
            'q' : q,
            'p' : p,
            'ec_name' : curveName,
            't' : t,
            'l' : l
        }

        for i in range (n):
            tmpUrl = url
            if(i/10 < 1):
                tmpUrl += "0" + str(i) + "/setup_variables_ec"
            else:
                tmpUrl += str(i) + "/setup_variables_ec"

            requests.post(tmpUrl, None, jsonBody)


        # Request public keys

        for i in range (n):
            tmpUrl = url
            if(i/10 < 1):
                tmpUrl += "0" + str(i) + "/get_public_key_ec"
            else:
                tmpUrl += str(i) + "/get_public_key_ec"

            response = requests.get(tmpUrl)
            print(response)
            publicKeys[i] = json.load(response)['pk']


        # Request encrypted shares

        for i in range (n):
            tmpUrl = url
            if(i/10 < 1):
                tmpUrl += "0" + str(i) + "/get_encrypted_shares_ec"
            else:
                tmpUrl += str(i) + "/get_encrypted_shares_ec"

            response = requests.get(tmpUrl).json()
            encryptedShares[i] = json.load(response)['eS']

    @app.post("/post_shares")
    def postShares():
        bodyContent = request.json
        shares = bodyContent['shares']
        if('plainShares' not in session):
            session['plainShares'] = [shares]
        else:
            auxShares = session.get('plainShares')
            auxShares.append(shares)
            session['plainShares'] = auxShares
        return "Shares shared"    


    @app.get("/compute_reveal")
    def computeReveal():
        if('plainShares' in session):
            plainShares = session.get('plainShares')
            if(len(plainShares) <= n - t):
                return "Not enough compromised participants"
            else:
                hS = functions.calculateSecrets(n, t, l, h, q, plainShares)
                session['hS'] = hS
                resultMatrix = functions.generateResultMatrix(l, t, w, q, h, hS)
                session['resultMatrix'] = resultMatrix
                return "Result matrix generated"
        
    @app.get("/get_result_from_matrix")
    def getResultFromMatrix():
        if('resultMatrix' in session):
            resultMatrix = session.get('resultMatrix')
            if(len(resultMatrix) != 0):
                i = randint(0, l)
                j = randint(0, l + t)

                return resultMatrix[i][j]
            else:
                return "Non valid result matrix generated"
        else:
            return "Result matrix not generated yet"