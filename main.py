import subprocess
import threading
from time import sleep

def runParticipant(port):
    command = "python -m flask --app participant:create_app(" + str(i) + ") run -p " + str(port)
    subprocess.run(command)

def runLedger(port, n, q):
    command = "python -m flask --app ledger:create_app(" + str(n) + "," + str(q) + ", false) run -p " + str(port)
    subprocess.run(command)    


# Main script to load all participants and the ledger for the simulation
n, q = 1, 523

# Load participants
for i in range(n):
    port = 5000 + i
    thread = threading.Thread(target=runParticipant, args=(port,))
    thread.start()


sleep(1)

#Load public ledger
thread = threading.Thread(target=runLedger, args=(6000,n,q,))
thread.start()