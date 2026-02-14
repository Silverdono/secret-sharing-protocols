import requests
import subprocess
import threading
from time import sleep
from ecpy.curves import Curve
import utils
from ldei import LDEI
import json
from random import randint
import time

def runParticipant(port):

    debug_mode = False

    command = "python -m flask --app participant:create_app(" + str(i) + "," + str(debug_mode) +") run -p " + str(port)
    subprocess.run(command) 

if __name__ == "__main__":
    # Main script to load all participants and the ledger for the simulation
    n, p = 11, 2147483647

    # Load participants
    for i in range(n):
        port = 5000 + i
        thread = threading.Thread(target=runParticipant, args=(port,))
        thread.start()


    sleep(1)

    ####### Ledger logic
    t = int(n/3) # Tolerance -- A bit arbitrary this value
    l = int(n - 2 * t) # l

    publicKeys = [-1] * n # Participants' public keys
    decodedPublicKeys = [-1] * n # Participants' decoded public keys used with Elliptic Curves
    encryptedShares = [-1] * n # Participants' encrypted shares
    ldeis = [-1] * n # Participants' computed LDEIs

    plainShares = [-1] * n # Participants' plain shares

    url = "http://127.0.0.1:50"

    elliptic = False

    start_total_time = time.time()
    if(not elliptic):

        h = utils.findGenerator(p) # Generator
        q = utils.findMultiplicativeOrder(h,p) # Multiplicative order of h in p

        jsonBody = {
            'n' : n,
            'q' : q,
            'p' : p,
            'h' : h,
            't' : t,
            'l' : l
        }

        # Setup variables
        start_time = time.time()
        for i in range (n):
            tmpUrl = url
            if(i/10 < 1):
                tmpUrl += "0" + str(i) + "/setup_variables"
            else:
                tmpUrl += str(i) + "/setup_variables"

            requests.post(tmpUrl, None, jsonBody)
        print("Time to setup variables: ", time.time() - start_time)

        # Request public keys
        start_time = time.time()
        for i in range (n):
            tmpUrl = url
            if(i/10 < 1):
                tmpUrl += "0" + str(i) + "/get_public_key"
            else:
                tmpUrl += str(i) + "/get_public_key"

            response = requests.get(tmpUrl)
            publicKeys[i] = response.json()['pk']
        print("Time to get public keys: ", time.time() - start_time)

        # Request encrypted shares
        start_time = time.time()
        for i in range (n):
            tmpUrl = url
            if(i/10 < 1):
                tmpUrl += "0" + str(i) + "/get_encrypted_shares"
            else:
                tmpUrl += str(i) + "/get_encrypted_shares"

            pkBody = {'pks' : json.dumps(publicKeys)}    

            response = requests.post(tmpUrl, None, pkBody)
            encryptedShares[i] = response.json()['eS']
        print("Time to get encrypted shares: ", time.time() - start_time)

        # Request computed LDEIs
        start_time = time.time()
        for i in range (n):
            tmpUrl = url
            if(i/10 < 1):
                tmpUrl += "0" + str(i) + "/get_ldei"
            else:
                tmpUrl += str(i) + "/get_ldei"


            pkBody = {'pks' : json.dumps(publicKeys)}
            
            response = requests.post(tmpUrl, None, pkBody)
            responseJson = response.json()
            tmpA = responseJson['a']
            tmpE = responseJson['e']
            tmpZ = responseJson['z']
            ldeis[i] = LDEI(tmpA, tmpE, tmpZ)
        print("Time to compute LDEIs: ", time.time() - start_time)

        if(len(ldeis) != n or len(publicKeys) != n or len(encryptedShares) != n):
            print("Not enough good participants to continue")
        else:    
            # Validate LDEIs
            start_time = time.time()
            for i in range(len(ldeis)):
                utils.verifyLDEI(ldeis[i],publicKeys,encryptedShares[i],n,t+l,q,p)
            print("Time to validate LDEIs: ", time.time() - start_time)
    else:

        curveName : str = 'secp256k1'
        ec = Curve.get_curve(curveName)
        q = ec._domain['order']


        jsonBody = {
            'n' : n,
            'ec_name' : curveName,
            't' : t,
            'l' : l
        }

        start_time = time.time()
        for i in range (n):
            tmpUrl = url
            if(i/10 < 1):
                tmpUrl += "0" + str(i) + "/setup_variables_ec"
            else:
                tmpUrl += str(i) + "/setup_variables_ec"

            requests.post(tmpUrl, None, jsonBody)
        print("Time to setup variables: ", time.time() - start_time)

        # Request public keys
        start_time = time.time()
        for i in range (n):
            tmpUrl = url
            if(i/10 < 1):
                tmpUrl += "0" + str(i) + "/get_public_key_ec"
            else:
                tmpUrl += str(i) + "/get_public_key_ec"

            response = requests.get(tmpUrl)
            publicKeys[i] = response.json()['pk']
            decodedPublicKeys[i] = ec.decode_point(publicKeys[i])

        print("Time to get public keys: ", time.time() - start_time)

        # Request encrypted shares
        start_time = time.time()
        for i in range (n):
            tmpUrl = url
            if(i/10 < 1):
                tmpUrl += "0" + str(i) + "/get_encrypted_shares_ec"
            else:
                tmpUrl += str(i) + "/get_encrypted_shares_ec"

            pkBody = {'pks' : publicKeys}

            response = requests.post(tmpUrl, None, pkBody)

            auxShare = response.json()['eS']
            decodedShares = []
            for point in auxShare:
                decodedShares.append(ec.decode_point(point))
            encryptedShares[i] = decodedShares
        print("Time to get encrypted shares: ", time.time() - start_time)

        # Request computed LDEIs
        start_time = time.time()
        for i in range (n):
            tmpUrl = url
            if(i/10 < 1):
                tmpUrl += "0" + str(i) + "/get_ldei_ec"
            else:
                tmpUrl += str(i) + "/get_ldei_ec"

            pkBody = {'pks' : publicKeys}

            response = requests.post(tmpUrl, None, pkBody)
            responseJson = response.json()
            tmpA = responseJson['a']
            finalA = []
            for point in tmpA:
                finalA.append(ec.decode_point(point))
            tmpE = responseJson['e']
            tmpZ = responseJson['z']
            ldeis[i] = LDEI(finalA, tmpE, tmpZ)    
        print("Time to compute LDEIs: ", time.time() - start_time)

        if(len(ldeis) != n or len(publicKeys) != n or len(encryptedShares) != n):
            print("Not enough good participants to continue")
        else:    
            # Validate LDEIs
            start_time = time.time()
            for i in range(len(ldeis)):
                utils.verifyLDEI_EC(ldeis[i],decodedPublicKeys,encryptedShares[i],n,t+l,q)
            print("Time to validate LDEIs: ", time.time() - start_time)


    if(len(encryptedShares) == n):
        start_time = time.time()
        for i in range (n):
            tmpUrl = url
            if(i/10 < 1):
                tmpUrl += "0" + str(i) + "/post_shares"
            else:
                tmpUrl += str(i) + "/post_shares"

            response = requests.get(tmpUrl)
            plainShares[i] = response.json()['shares']
        print("Time to get plain shares: ", time.time() - start_time)

    sharesMatrix = []
    if(len(plainShares) == n):
        sharesMatrix = plainShares
    else:
        sharesMatrix = utils.calculateSecrets(n,t,l,h,q,plainShares,False) # Elliptic curve as false as this step is not implemented for that case
    start_time = time.time()
    w = randint(0, q) # Base used for vandermonde matrix smaller than multiplicative order of q
    vandermonde = utils.generateVandermondeMatrix(t,l,w,q) # Generate Vandermonde matrix for output
    outputMatrix = utils.generateResultMatrix(vandermonde, sharesMatrix)
    print("Time to compute result matrix: ", time.time() - start_time)
    print("TOTAL TIME: ", time.time()-start_total_time)