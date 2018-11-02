import argparse
import re

class HashRegexp(object):
    def __init__(self, algos, func):
        self.algos = algos
        self.func = func


allRegexps = [
    HashRegexp(['MD5', 'MD4'], lambda x: re.compile(r'^[a-f0-9]{32}(:.+)?$').match(x)),
    HashRegexp(['MD5 Crypt'], lambda x: re.compile(r'^\$1\$[a-z0-9\/.]{0,8}\$[a-z0-9\/.]{22}(:.*)?$').match(x)),
    HashRegexp(['SHA-1', 'Tiger-160'], lambda x: re.compile(r'^[a-f0-9]{40}(:.+)?$').match(x)),
    HashRegexp(['SHA-1(Base64)'], lambda x: re.compile(r'^{SHA}[a-z0-9\/+]{27}=$').match(x)),
    HashRegexp(['SHA-256'], lambda x: re.compile(r'^[a-f0-9]{64}(:.+)?$').match(x)),
    HashRegexp(['SHA-384'], lambda x: re.compile(r'^[a-f0-9]{96}$').match(x)),
    HashRegexp(['bcrypt'], lambda x: re.compile(r'^(\$2[axy]|\$2)\$[0-9]{2}\$[a-z0-9\/.]{53}$').match(x)),
    HashRegexp(['Tiger-192'], lambda x: re.compile(r'^[a-f0-9]{48}$').match(x)),
    HashRegexp(['MySQL323', 'DES(Oracle)'], lambda x: re.compile(r'^[a-f0-9]{16}$').match(x)),
]

def findHash(hash):
    matched_algo = []
    for regexp in allRegexps:
        if regexp.func(hash):
            matched_algo += regexp.algos

    return matched_algo

parser = argparse.ArgumentParser(description='Analyse a hash')
parser.add_argument('hash', metavar='INPUT', type=str, help='The Hash to analyse')

args = parser.parse_args()

matched_hash = findHash(args.hash)

for algo in matched_hash:
    print(algo)
