# SSH Known_Hosts Bruteforce

A tool to bruteforce hashed SSH known_hosts files. It has the ability to parse wordlists and history files for IP addresses and hostnames to test.

## Overview

Basic usage:

```
SSH known_hosts file bruteforce
 (c) 2013 jtRIPper

usage: bruteforce_known_hosts.py [-h] [--network NETWORK] [--file FILE]
                                 [--history HISTORY] [--wordlist WORDLIST]
                                 [--output OUTPUT] [--disable-wordlist]
                                 [--disable-history] [--disable-network]

optional arguments:
  -h, --help            show this help message and exit
  --network NETWORK, -n NETWORK
                        CIDR of network to test (e.g. 192.168.0.0/16).
  --file FILE, -f FILE  The SSH known_hosts file.
  --history HISTORY     Directory to search for history files.
  --wordlist WORDLIST, -w WORDLIST
                        Wordlist directory.
  --output OUTPUT, -o OUTPUT
                        Output file.
  --disable-wordlist, -r
                        Disable wordlist search.
  --disable-history, -p
                        Disable history search.
  --disable-network, -q
                        Disable network search.
```


