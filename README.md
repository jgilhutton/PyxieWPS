# pyxiewps overview

Pyxiewps is a wireless attack tool writen in python to retrieve the WPS pin of any vulnerable AP in seconds.
It is meant for educational purposes only. All credits for the research go to Dominique Bongard.

It uses:
  Reaver: Reaver 1.5.2 mod by t6_x & DataHead & Soxrok2212 & Wiire & kib0rg
  Pixiewps: by wiire <wi7ire@gmail.com>
  Aircrack: http://www.aircrack-ng.org
  Macchanger: by Alvaro Lopez Ortega
  
There are already a bunch of tools, reaver included, that can attack an access point (AP) using the Pixie Dust vulnerability but I wanted to do something automatic, fast and user friendly, so here we are.

I also wrote this program to be used on the fly as I walk in the city. If the router is vulnerable, this script uses reaver and pixiewps to retrieve the AP password in, at least, 11 seconds. YUP! You get the WPA password of any vulnerable AP in 11 seconds using the fastest configuration.

It enumerates all the APs with active WPS, tries to get the PKE, PKR, E-NONCE, R-NONCE, AUTHKEY, HASH1 and 2 using the patched version of reaver, then passes all that information to pixiewps program so that it can retrieve the WPS pin, and finally runs reaver again with the pin that pixiewps found to get the AP WPA password.

Please report any bugs to pyxiewps@gmail.com

# USAGE
  
	-r --use-reaver          Use reaver to get all the AP information.              [False]
	-p --use-pixie           Once all the data is captured with reaver              [False]
	                         the script tries to get the WPS pin with pixiewps.
	-w --wash-time [time]    Set the time used to enumerate all the WPS-active APs. [15]
	-t --time [time]         Set the time used to get the hex data from the AP.       [6]
	-c --channel [channel]   Set the listening channel to enumerate the WPS-active APs.
	                         If not set, all channels are listened.
	-P --prompt              If more than one WPS-active AP is found, ask the user [False]
	                         the target to attack.
	-o --output [file]       Outputs all the data into a file.
	-f --pass                If the WPS pin is found, the script uses reaver again to retrieve
	                         the WPA password of the AP.
	-q --quiet               Doesn't print the AP information. Will print the WPS pin and pass if found.
	-F --forever             Runs the program on a While loop so the user can scan and attack a hole
	                         zone without having to execute the program over and over again.
	-O --override            Doesn't prompt the user if the WPS pin of the current AP has already
	                         been found. DOESN'T SKIP THE AP, the script attacks it again.
	                         
#USAGE EXAMPLE

  python pyxiewps-ingles.py -r -p -w 15 -t 6 -c 7 -P -o file.txt -f
  python pyxiewps-ingles.py --use-reaver --use-pixie --wash-time 15 --time 6 --channel 7 --prompt --output file.txt -h
