#!/usr/bin/env python

import os
import sys
import argparse

def root_check():
    if os.geteuid() == 0:
        pass
    else:
        print("[-] Please run as root")
        sys.exit()

def pass_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', dest='TARGET', help="Specify the address to perform scan. Format: ip/suffix")
    options = parser.parse_args() # returns only options, unlike optparse which returns options and arguments

    # Validating arguments
    if not options.TARGET:
        parser.error("Missing argument. Use -h or --help for more info")
    else:
        return options.TARGET

def target_validation(target):

    # Splitting input into ip and prefix to validate then separately
    try:
        ip = target.split('/')[0]
        prefix = target.split('/')[1]

        flag = False

        # Validating IP (Checking if entered IP is among the range of any private addresses : 10.0.0.0 - 10.255.255.255, 172.16.0.0 - 172.16.255.255, 192.168.0.0 - 192.168.255.255)
        octect = ip.split('.')
        if not ( (octect[0] == '10' and '0' <= octect[1] <= '255' and '0' <= octect[2] <= '255' and '0' <= octect[3] <= '255') or (octect[0] == '172' and octect[1] == '16' and '0' <= octect[2] <= '255' and '0' <= octect[3] <= '255') or (octect[0] == '192' and octect[1] == '168' and '0' <= octect[2] <= '255' and '0' <= octect[3] <= '255')):
            print("[-] Invalid IP\n    Should be a private IP: 10.0.0.0 - 10.255.255.255, 172.16.0.0 - 172.16.255.255, 192.168.0.0 - 192.168.255.255")
            flag = True
        else:
            pass

        # Validating prefix
        if not '1' <= prefix <= '32':
            print("[-] Invalid prefix value\n    Value should be within (1 - 32) range")
            flag = True
        else:
            pass

        # Deciding whether to continue program or not based on IP and prefix validation
        if flag == True:
            sys.exit()
        else:
            pass
    except IndexError:
        print("[-] Incomplete input. Use -h or --help for more info")
        sys.exit()
        
# Checking if running as root
root_check()

# Defining and parsing arguments to pass while running the script
target = pass_arguments()

# Validating if the user input is of right format
target_validation(target)

# Importing scan script dependent on sacpy if cleared from above
from scan import scan
from scan import result_display

# Scanning with the target provided
answered = scan(target)

# Displaying scan results
result_display(answered)