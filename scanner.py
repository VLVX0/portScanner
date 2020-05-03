import socket
import threading
import time
import sys

host = input("Please enter the IP you want to scan: ")
vulnports = [21,22,23,25,53,80,88,443,110,111,135,137,138,139,143,445,993,995,1723,1433,1434,3306,3389,5900,8080]

openPorts = []

def portScanner(i):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    s.settimeout(0.1)
    if s.connect_ex((host, i)):
        print("closed " + str(i))
    else:
        print("OPEN   " + str(i))
        openPorts.append(i)
        s.close()

threads = []

def threadScannerVuln(vulnports):
    for i in vulnports:
        t = threading.Thread(target = portScanner, args = [i])
        t.start()
        threads.append(t)
    for thread in threads:
        thread.join()

def portScannerRange(i):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.1)
    if s.connect_ex((host, i)):
        print("closed " + str(i))
    else:
        print("OPEN   " + str(i))
        openPorts.append(i)
        s.close()

def threadScanner(a, b):
    for i in range(a, b):
        t = threading.Thread(target = portScannerRange, args = [i])
        t.start()
        threads.append(t)
    for thread in threads:
        thread.join()

while True:
    print("Option 1 Port 0 - 1023\nOption 2 Port 1024 - 49151\nOption 3 Port 49152 - 65535\nOption 4 Vulnerable Ports")
    option = int(input("Enter 1, 2, 3 or 4: "))
    if option == 1 or option == 2 or option == 3 or option == 4 or option == 5:
        break

if option == 1:
    start = time.perf_counter()
    threadScanner(0, 1025)
    finish = time.perf_counter()
    print("Finished in " + str(finish - start) + " seconds")
    print("Open ports:")
    for i in openPorts:
        sys.stdout.write(str(i) + " ")
elif option == 2:
    start = time.perf_counter()
    threadScanner(1025, 49152)
    finish = time.perf_counter()
    print("Finished in " + str(finish - start) + " seconds")
    print("Open ports:")
    for i in openPorts:
        sys.stdout.write(str(i) + " ")
elif option == 3:
    start = time.perf_counter()
    threadScanner(49152, 65536)
    finish = time.perf_counter()
    print("Finished in " + str(finish - start) + " seconds")
    print("Open ports:")
    for i in openPorts:
        sys.stdout.write(str(i) + " ")
elif option == 4:
    start = time.perf_counter()
    threadScannerVuln(vulnports)
    finish = time.perf_counter()
    print("Finished in " + str(finish - start) + " seconds")
    print("Open ports:")
    for i in openPorts:
        sys.stdout.write(str(i) + " ")
else:
    print("Enter correct option")
