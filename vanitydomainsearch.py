import sys
import pythonwhois
import json
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--whitelist', default=[], help='Allowed TLD\'s')
parser.add_argument('--blacklist', default=[], help='Disallowed TLD\'s')
parser.add_argument('-w', '--wordlist', required=True)
args = parser.parse_args()

def build_tld_dict():
    if len(args.whitelist) > 0:
        tldlist = args.whitelist.split(',')
    else:
        #crawl iana site
        sys.exit('Running without TLD whitelist is currently not supported')
    if len(args.blacklist) > 0:
        for blacklisted_tld in args.blacklist.split(','):
            if blacklisted_tld in tldlist:
                tldlist.remove(blacklisted_tld)
    tlddict = {}
    for tld in tldlist:
        length = len(tld)
        if length not in tlddict:
            tlddict[length] = []
        tlddict[length].append(tld)
    return tlddict

def retrieve_words(filename):
    wordlist = open(filename, 'r')
    return wordlist.read().splitlines()

def find_candidates():
    tld_dict = build_tld_dict()
    words = retrieve_words(args.wordlist)
    candidates = []
    for word in words:
        for length in tld_dict:
            tlds = tld_dict[length]
            ext = word[-length:]
            if ext in tlds and length < len(word):
                domain = word[:-length] + '.' + ext
                candidates.append(domain)
    return candidates

candidates = find_candidates()
if len(candidates) > 0:
    print('Found ' + str(len(candidates)) + ' candidate(s):')
    for candidate in candidates:
        print(candidate)
else:
    sys.exit('No candidates found.')

querywhois = input('query whois? (y/n)') == 'y'
if querywhois:
    available = 'Available domains: '
    unavailable = 'Unavailable domains: '
    for candidate in candidates:
        print('querying whois for ' + candidate)
        whois = pythonwhois.get_whois(candidate)
        if 'id' in whois:
            unavailable = unavailable + candidate + ' '
        else:
            available = available + candidate + ' '
    print(available)
    print(unavailable)
