# SSH Known_Hosts Bruteforce

A tool to bruteforce hashed SSH known_hosts files. It has the ability to parse wordlists and history files for IP addresses and hostnames to test.

## Overview

Basic usage:

```
  SSH known_hosts file bruteforce
   (c) 2013 jtRIPper

usage: brute.py [-h] [--network NETWORK] [--file FILE] [--history HISTORY]
                [--wordlist WORDLIST] [--output OUTPUT]

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
```


