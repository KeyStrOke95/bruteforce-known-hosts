#!/usr/bin/python

# bruteforce_known_hosts.py
# (C) 2013 jtRIPper
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 1, or (at your option)
# any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

import base64
from hashlib import sha1
import hmac
import os
import sys
import re
import ipaddr
import threading
import time
import argparse

BOLD = '\033[1m'
BLUE = '\033[34m'
GREEN = '\033[32m'
YELLOW = '\033[33m'
RED = '\033[91m'
ENDC = '\033[0m'

NOTICE = " %s[%s%s+%s%s]%s" % (GREEN, ENDC, BOLD, ENDC, GREEN, ENDC)
FOUND  = " %s[%s%s*%s%s]%s" % (BLUE, ENDC, GREEN, ENDC, BLUE, ENDC)
ERROR  = " %s[%s%s!%s%s]%s" % (RED, ENDC, YELLOW, ENDC, RED, ENDC)

class known_hosts:
  def __init__(self, (encoded_salt, encoded_host)):
    self.salt         = base64.b64decode(encoded_salt)
    self.encoded_host = base64.b64decode(encoded_host)
    self.host         = None

  def encode_hostname(self, ip):
    if not self.host:
      if hmac.new(self.salt, ip, sha1).digest() == self.encoded_host:

        if ":" in ip:
          self.host = re.search("\\[([^\\]]+)]:([0-9]+)", ip).groups()
          self.host = self.host[0] + ":" + self.host[1]
        else:
          self.host = ip

        return True
      else:
        return False

def parse_known_hosts(file, output):
  try:
    os.stat(file)
  except:
    print "%s Provided known_hosts file (%s%s%s) does not exist. Quitting." % (ERROR, YELLOW, file, ENDC)
    quit()

  known_hosts_file = open(file, 'r')
  hosts_list = []
 
  for line in known_hosts_file.readlines():
    try:
      hosts_list.append(known_hosts(re.search("^\\|1\\|([^|]+)\\|([^ ]+)", line).groups()))
    except:
      if ":" in line:
        ip = re.search("\\[([^\\]]+)]:([0-9]+)", line).groups()
        ip = ip[0] + ":" + ip[1]
      else:
        ip = re.search("^([^ ]+)", line).group(0)

      print "%s Found host: %s%s%s!" % (FOUND, YELLOW, ip, ENDC)
      if output:
        open(output, "a").write(ip + "\n")

  return hosts_list

def check_hosts(hosts_list, ip_list, output):
  for ip in ip_list:
    for host in hosts_list:
      if host.encode_hostname(ip):
        print "%s Found host: %s%s%s!" % (FOUND, YELLOW, host.host, ENDC)
        if output:
          open(output, "a").write(host.host + "\n")

def gen_ip_addresses(hosts_list, network, output):
  ip_list = []
  threads = []

  for ip in ipaddr.IPv4Network(network).iterhosts():
    ip_list.append(str(ip))
    if len(ip_list) == 1000:
      thread = threading.Thread(target=check_hosts, args=(hosts_list, ip_list, output, ))
      thread.start()
      threads.append(thread)
      ip_list = []

  if ip_list != []:
    thread = threading.Thread(target=check_hosts, args=(hosts_list, ip_list, output, ))
    thread.start()
    threads.append(thread)

  for thread in threads:
    thread.join()

def gen_domain_names(hosts_list, directory, output):
  threads = []
  word_list = []

  for file in os.listdir(directory):
    try:
      for line in open(directory + "/" + file, "r").readlines():
        word_list += line.rstrip().split()

        if len(word_list) >= 1000:
          thread = threading.Thread(target=check_hosts, args=(hosts_list, word_list, output, ))
          thread.start()
          threads.append(thread)
          word_list = []
    except:
      pass

    if word_list != []:
      thread = threading.Thread(target=check_hosts, args=(hosts_list, word_list, output, ))
      thread.start()
      threads.append(thread)

  for thread in threads:
    thread.join()

  return hosts_list

def check_history_files(hosts_list, directory, output):
  for file in os.listdir(directory):
    if "history" not in file:
      continue

    for line in open(directory + "/" + file, "r").readlines():
      try:
        ips = re.search("([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)", line).groups()

        try:
          ips += ("[%s]:%s" % (ips[0], re.search("-[pP] ?([0-9]+)", line).group(1)), )
        except:
          pass

        check_hosts(hosts_list, ips, output)
      except:
        pass

  return hosts_list

def main():
  print "SSH known_hosts file bruteforce"
  print " (c) 2013 %sjtRIPper%s\n" % (RED, ENDC)

  parser = argparse.ArgumentParser()
  parser.add_argument("--network", "-n", help="CIDR of network to test (e.g. 192.168.0.0/16).", default="0.0.0.0/0")
  parser.add_argument("--file", "-f", help="The SSH known_hosts file.", default=os.getenv("HOME") + "/.ssh/known_hosts")
  parser.add_argument("--history", help="Directory to search for history files.", default=os.getcwd())
  parser.add_argument("--wordlist", "-w", help="Wordlist directory.", default=os.getcwd())
  parser.add_argument("--output", "-o", help="Output file.", default=None)
  parser.add_argument("--disable-wordlist","-r", help="Disable wordlist search.", action='count')
  parser.add_argument("--disable-history", "-p", help="Disable history search.", action='count')
  parser.add_argument("--disable-network", "-q", help="Disable network search.", action='count')
  args = parser.parse_args()

  start = time.time()

  print "Beginning bruteforce at: %s%s%s" % (GREEN, time.asctime(), ENDC)
  print "\nSettings:"
  print "%s known_hosts file:   %s%s%s" % (NOTICE, YELLOW, args.file, ENDC)
  if not args.disable_network:
    print "%s Network:            %s%s%s" % (NOTICE, YELLOW, args.network, ENDC)
  print "%s Output file:        %s%s%s" % (NOTICE, YELLOW, args.output, ENDC)
  if not args.disable_history:
    print "%s History directory:  %s%s%s" % (NOTICE, YELLOW, args.history, ENDC)
  if not args.disable_wordlist:
    print "%s Wordlist directory: %s%s%s\n" % (NOTICE, YELLOW, args.wordlist, ENDC)
  print "Found hosts:"

  if args.output:
    try:
      open(args.output, "w").close()
    except:
      print "%s Provided output file (%s%s%s) cannot be opened! Quitting." % (ERROR, YELLOW, args.output, ENDC)
      quit()
 
  hosts_list = parse_known_hosts(args.file, args.output)
  if not args.disable_history:
    hosts_list = check_history_files(hosts_list, args.history, args.output)
  if not args.disable_wordlist:
    hosts_list = gen_domain_names(hosts_list, args.wordlist, args.output)
  if not args.disable_network:
    gen_ip_addresses(hosts_list, args.network, args.output)

  print "\nBruteforce completed at: %s%s%s (%s%d%s seconds)" % (GREEN, time.asctime(), ENDC, BOLD, time.time() - start, ENDC)

if __name__ == "__main__":
  main()

