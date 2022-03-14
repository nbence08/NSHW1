import re
import socket
import argparse
from Crypto.Hash import SHA1
import string
import requests
import os

def evaluate(eq):
    eq = re.split("^\\d{2}\\.", eq)[1]
    eq = re.split("=", eq)[0]

    plusSplit = re.split("\\+", eq)

    accu = 0
    for idx, plus in enumerate(plusSplit):
        minusSplit = re.split("-", plus)
        accu += int(minusSplit[0])

        for minus in minusSplit[1:]:
            accu -= int(minus)
    return accu


def knockPorts(ports):
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.3)

        try:
            sock.connect((host, port))
        except TimeoutError:
            sock.close()
            continue
        sock.close()


def sha1Hash(byteObj):
    h = SHA1.new()
    h.update(byteObj)
    return h.hexdigest()


def proofOfWork(stringValue):
    charList = []
    for letter in string.ascii_uppercase:
        charList.append(letter)
    for i in range(0, 10):
        charList.append(str(i))

    maxLetter = len(charList)
    iterTable = [0]

    raw = ""
    hashValue = ""
    while(not re.match("^0000", hashValue)):
        raw = ""
        for idx, num in enumerate(iterTable):
            raw += charList[num]
        hashValue = sha1Hash((stringValue+raw).encode("ascii"))
        carry = 0
        iterTable[-1] += 1
        for i in range(0, len(iterTable)).__reversed__():
            iterTable[i] += carry
            carry = 0
            if iterTable[i] == maxLetter:
                iterTable[i] = 0
                carry = 1
                if i == 0:
                    iterTable = [i for i in range(0,len(iterTable))]
                    iterTable.append(0)
                    carry = 0
    return stringValue+raw



parser = argparse.ArgumentParser(description='NetSec HW')
parser.add_argument("-n", "--neptun", type=str, nargs=1, help="Neptun code to run the app for")

host = '152.66.249.144'
ports = [1337, 2674, 4011]
commPort = 8888
args = parser.parse_args()
neptun = args.__getattribute__("neptun")[0].upper()
neptunCoded = neptun.encode("ascii")

knockPorts(ports)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((host, commPort))
msg = sock.recv(30)

if(msg.decode("ascii") != 'Give me your neptun code: '):
    raise ValueError("ERROR: message must be \"Give me your neptun code: \"")

sock.send(neptunCoded)
print(sock.recv(100).decode("ascii"))
msg=sock.recv(1000).decode("ascii")

firstPart = re.split("equations!", msg)[0]
numOfEqs = int(re.split("I will send you", firstPart)[1])

print(numOfEqs)

eq = msg.split("\n")[2]

result = evaluate(eq)
msg = str(result).encode("ascii")
sock.send(msg)
print(eq + " " + str(result))

for i in range(1, numOfEqs):
    eq = sock.recv(1000).decode("ascii")

    result = evaluate(eq)
    msg = str(result).encode("ascii")
    sock.send(msg)
    print(eq + " " + str(result))

lastRes = str(msg.decode("ascii"))

msg=sock.recv(1000).decode("ascii")
print(msg)
msg=sock.recv(1000).decode("ascii")
print(msg)

concat = neptun+lastRes
concat = concat.encode("ascii")

hash = sha1Hash(concat)

sock.send(hash.encode("ascii"))

msg=sock.recv(1000).decode("ascii")
print(msg)

powValue = proofOfWork(concat.decode("ascii"))
sock.send(powValue.encode("ascii"))

msg=sock.recv(1000).decode("ascii")
print(msg)

msg=sock.recv(1000).decode("ascii")
print(msg)
msg=sock.recv(1000).decode("ascii")
print(msg)
msg=sock.recv(1000).decode("ascii")
print(msg)


url = re.search(r"http://(\d{1,3}\.){3}(\d{1,3})", str(msg))[0]
password = re.search(r"'.*'", msg)[0][1:-1]
postUrl = url+"/?"

postData = {
    "neptun":neptun,
    "password": password
}

loginResp = requests.post(postUrl, postData)

cookies = loginResp.cookies

getcert = requests.get(url+"/getcert.php", cookies=cookies)
getkey = requests.get(url+"/getkey.php", cookies=cookies)

urls = re.search(r"https://(\d{1,3}\.){3}(\d{1,3})", str(msg))[0]

certPath = "cert.pem"
keyPath = "key.pem"

with open(certPath, "wb") as cert:
    cert.write(getcert.content)
with open(keyPath, "wb") as key:
    key.write(getkey.content)

cert = (certPath, keyPath)
headers = {
    "User-Agent":"CrySyS"
}

gets = requests.get(urls, cert=cert, verify=False,headers=headers)

os.remove(certPath)
os.remove(keyPath)

print(gets.text)