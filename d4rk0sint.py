#!/bin/env python3
import sys, os, cv2, threading
from colorama import init, Fore, Style, Back
from time import sleep
from queue import Queue
from prettytable import PrettyTable
import argparse, shodan

init()
colourtheme1, colourtheme2 = "\u001b[38;5;46m", "\u001b[38;5;50m"
warningcolour, successcolour, infocolour = "\u001b[38;5;220m", "\u001b[38;5;46m", "\u001b[38;5;39m"
errorcolour, reverse, fullreset = "\u001b[38;5;160m", "\u001b[7m", "\u001b[0m"

def clear():
    os.system('clear') if not sys.platform == "win32" else print('\n' * 100)

banner = f'''
┌───────────────────────────────────────────────────────────────────────┐
│██████╗ ██╗  ██╗██████╗ ██╗  ██╗ ██████╗ ███████╗██╗███╗   ██╗████████╗│
│██╔══██╗██║  ██║██╔══██╗██║ ██╔╝██╔═████╗██╔════╝██║████╗  ██║╚══██╔══╝│
│██║  ██║███████║██████╔╝█████╔╝ ██║██╔██║███████╗██║██╔██╗ ██║   ██║   │
│██║  ██║╚════██║██╔══██╗██╔═██╗ ████╔╝██║╚════██║██║██║╚██╗██║   ██║   │
│██████╔╝     ██║██║  ██║██║  ██╗╚██████╔╝███████║██║██║ ╚████║   ██║   │
│╚═════╝      ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝   │
├────────────────────────────────────┬─────────────────┬────────────────┤
│             By C.Z3R0              │   Sec-Student   │ Version: 1.0.0 │
└────────────────────────────────────┴─────────────────┴────────────────┘
'''

clear()
print(banner)

parser = argparse.ArgumentParser(description='Find Vulnerable RTSP Cameras Around the World')
parser.add_argument('Your-api-key', metavar='ShodanAPIkey', type=str, help='Your Shodan API Key')
parser.add_argument('-t', metavar='Threads', type=int, help='Threads to use', default=15)
args = parser.parse_args()

def warning(message): print(f'[{reverse}{warningcolour}!{fullreset}] {str(message)}')
def success(message): print(f'[{reverse}{successcolour}!{fullreset}] {str(message)}')
def info(message): print(f'[{reverse}{infocolour}!{fullreset}] {str(message)}')    
def error(message): print(f'[{reverse}{errorcolour}!{fullreset}] {str(message)}')

api = shodan.Shodan(args.apikey)
try:
    info('Searching...')
    results = api.search('rtsp')
    success(str(len(results['matches'])) + ' Results')
except shodan.exception.APIError as e:
    error(e)
    sys.exit()

x = PrettyTable()
x.field_names = ["IP", "Domain", "Country", "City"]

for target in results['matches']:
    targetdomain = successcolour + target["domains"][0] + fullreset if target["domains"] else ""
