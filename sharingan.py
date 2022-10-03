#!/usr/bin/python3

from termcolor import colored
import subprocess
import sys

inscope = sys.argv[1]

with open(inscope, 'r') as file:
	for line in file.readlines():
		if "*" in line:
			target = line[2:] # removing the first two which are *.  so it's:  nflxvideo.net
			print(colored(f"[+] Start Recon for ", 'red'), end='')
			print(colored(target, "red", attrs=['bold']))
			subprocess.call(['sharingan', target])
		else:
			print(colored(f"[+] Start Recon for ", 'red'), end='')
			print(colored(line, "red", attrs=['bold']))
			subprocess.call(['sharingan', line])
