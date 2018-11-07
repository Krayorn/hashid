import argparse
import re

class HashRegexp(object):
    def __init__(self, algos, func):
        self.algos = algos
        self.func = func

class Algo(object):
    def __init__(self, name, hashcat):
        self.name = name
        self.hashcat = hashcat

md5 = Algo('MD5', 0)
md4 = Algo('MD4', 900)
md5_crypt = Algo('MD5 Crypt', 500)
sha_1 = Algo('SHA-1', 100)
tiger_160 = Algo('Tiger-160', None)
sha_1_base64 = Algo('SHA-1(Base64)', 101)
sha_256 = Algo('SHA-256', 1400)
sha_384 = Algo('SHA-384', 10800)
bcrypt = Algo('bcrypt', 3200)
tiger_192 = Algo('Tiger-192', None)
mysql323 = Algo('MySQL323', 200)
des_oracle = Algo('DES(Oracle)', 3100)

allAlgos = [
    md5,
    md4,
    md5_crypt,
    sha_1,
    tiger_160,
    sha_1_base64,
    sha_256,
    sha_384,
    bcrypt,
    tiger_192,
    mysql323,
    des_oracle
]

allRegexps = [
    HashRegexp([md5, md4], lambda x: re.compile(r'^[a-f0-9]{32}(:.+)?$').match(x)),
    HashRegexp([md5_crypt], lambda x: re.compile(r'^\$1\$[a-z0-9\/.]{0,8}\$[a-z0-9\/.]{22}(:.*)?$').match(x)),
    HashRegexp([sha_1, tiger_160], lambda x: re.compile(r'^[a-f0-9]{40}(:.+)?$').match(x)),
    HashRegexp([sha_1_base64], lambda x: re.compile(r'^{SHA}[a-z0-9\/+]{27}=$').match(x)),
    HashRegexp([sha_256], lambda x: re.compile(r'^[a-f0-9]{64}(:.+)?$').match(x)),
    HashRegexp([sha_384], lambda x: re.compile(r'^[a-f0-9]{96}$').match(x)),
    HashRegexp([bcrypt], lambda x: re.compile(r'^(\$2[axy]|\$2)\$[0-9]{2}\$[a-z0-9\/.]{53}$').match(x)),
    HashRegexp([tiger_192], lambda x: re.compile(r'^[a-f0-9]{48}$').match(x)),
    HashRegexp([mysql323, des_oracle], lambda x: re.compile(r'^[a-f0-9]{16}$').match(x)),
]

def findHash(hash):
    matched_algo = []
    for regexp in allRegexps:
        if regexp.func(hash):
            matched_algo += regexp.algos

    return matched_algo

parser = argparse.ArgumentParser(description='Analyse a hash')
parser.add_argument('hash', metavar='INPUT', type=str, help='The Hash to analyse', nargs='?')
parser.add_argument('--list', help='list all hash known by the tool', action='store_true')
parser.add_argument('--hashcat', help='give the hashcat command', action='store_true')

args = parser.parse_args()

if args.list:
    for algo in allAlgos:
        print(algo.name)
else:
    matched_hash = findHash(args.hash)

    for algo in matched_hash:
        if args.hashcat:
            if algo.hashcat:
                print(f'{algo.name}: {algo.hashcat}')
            else:
                print(f'{algo.name}: there is no Haschat for this algo')
        else:
            print(algo.name)
