# DISCLAMER: due to massive changes in debian distributions, including new Iproute2 and systemd, this script won't work anymore. In order fot it to work flawlessly, you'll need old net-tools installed in your system (ifconfig, arp, etc)

# pyxiewps overview

Pyxiewps is a wireless attack tool written in python that uses reaver, pixiewps and aircrack to retrieve the WPS pin of any vulnerable AP in seconds.
It's a wrapper.
It is meant for educational purposes only. All credits for the research go to Dominique Bongard.

It uses:
  Reaver: Reaver 1.5.2 mod by t6_x & DataHead & Soxrok2212 & Wiire & kib0rg
  Pixiewps: by wiire <wi7ire@gmail.com>
  **Last version** of Aircrack: http://www.aircrack-ng.org

There are already a bunch of tools, reaver included, that can attack an access point (AP) using the Pixie Dust vulnerability but I wanted to do something automatic, fast and user friendly, so here we are.

I also wrote this program to be used on the fly as I walk in the city. If the router is vulnerable, this script uses reaver and pixiewps to retrieve the AP password in, at least, 9 seconds. YUP! You get the WPA password of any vulnerable AP in 9 seconds using the fastest configuration.

It enumerates all the APs with active WPS, tries to get the PKE, PKR, E-NONCE, R-NONCE, AUTHKEY, HASH1 and 2 using the patched version of reaver, then passes all that information to pixiewps program so that it can retrieve the WPS pin, and finally runs reaver again with the pin that pixiewps found to get the AP WPA password.

Please report any bugs to pyxiewps@gmail.com ||
Twitter: https://twitter.com/jgilhutton ||
Demonstration: https://www.youtube.com/watch?v=AuNO_O_RkcE

# USAGE
  	python pyxiewps-[LANGUAGE].py <arguments>
  	
  Individual options:

        -p --use-pixie               Once all the data is captured with reaver                [False]
                                     the script tries to get the WPS pin with pixiewps.
        -a --airodump-time [time]    Airodump spends this amount of time enumerating APs      [3]
        -t --time [time]             Set the time used to get the hex data from the AP.       [6]
        -c --channel [channel]       Set the listening channel to enumerate the WPS-active APs.
                                     If not set, all channels are listened.
        -P --prompt                  If more than one WPS-active AP is found, ask the user    [False]
                                     the target to attack.
        -o --output [file]           Outputs all the data into a file.
        -f --pass                    If the WPS pin is found, the script uses reaver again to retrieve
                                     the WPA password of the AP.
        -q --quiet                   Doesn't print the AP information. Will print the WPS pin and pass if found.
        -F --forever                 Runs the program on a While loop so the user can scan and attack a hole
                                     zone without having to execute the program over and over again.
        -A --again                   Target is attacked again in case of success without prompting the user.
        -s --signal [-NUMBER]        APs with RSSI lower than NUMBER will be ignored          [-100]
                                     A value of "-50" will ignore APs with RSSI between
                                     -100 and -51 and will attack APs which RSSI goes from -50 to 0
        -M --max-aps [number]        Max amount of APs to be attacked.
        -m --mode [mode]             Set the mode preset. Any preset option can be override
                                     by giving its argument and value on the commandline.
                                     i.e: "-m DRIVE -t 10"

  Available modes:

        WALK:
                [-p] [-f] [-a 4] [-t 8] [-F] [-M 2]
                Tries to get the WPS pin
                4 seconds will be used to enumerate the APs
                8 seconds will be used to fetch the AP information
                Will try to get the password
                The program will run in a while loop.
                A max amount of 2 APs will be attacked
                AP won't be atacked again if failed once
        DRIVE:
                [-p] [-t 10] [-F] [-M 1]
                Tries to get the WPS pin
                3 seconds will be used to enumerate the APs
                10 seconds will be used to fetch the AP information
                Won't try to get the password
                The program will run in a while loop.
                Only one AP will be attacked
                AP won't be atacked again if failed once
        STATIC:
                [-p] [-f] [-a 5] [-t 10] [-P] [-O]
                Tries to get the WPS pin
                5 seconds will be used to enumerate the APs
                10 seconds will be used to fetch the AP information
                Will try to get the password
                The program will run only once
                User will be prompted for an AP to attack
                AP will be atacked again if failed once
	                         
#USAGE EXAMPLES

[+] Enumerate the WPS active APs, fetch the AP information with Reaver, use Pixiewps to get the WPS pin, gives Reaver 6 seconds to fetch the information, uses channel 7, prompt which AP you want to attack, outputs data into a file and tries to get the password running Reaver with the found pin.

        python pyxiewps-[LANGUAGE].py -p -t 6 -c 7 -P -o file.txt -f
        python pyxiewps-[LANGUAGE].py --use-pixie --time 6 --channel 7 --prompt --output file.txt --pass

[+] Same as above but it doesn't prompt for the target, runs in a while loop and override already cracked passwords. This is useful when you try to attack a hole zone as you run the script only once.

        python pyxiewps-[LANGUAGE].py -p -t 6 -c 7 -F -A -o file.txt -f

[+] Use DRIVE mode.

        pyxiewps -m DRIVE

# Known problems

[+] ///WILL WARN/// If the program is running in a small console, Pyxiewps will fail at parsing the Airodump's data due it's output format or sometimes some ESSID names will show truncated. To avoid this problem maximize the window.

[+] ///FIXED/// When the program finishes and is done cleaning the interface stuff, you probably won't have the prompt in the console anymore. That's because Airodump doesn't have a good relationship with Python (It's a good way to say I don't have a #@$ing idea of what the @#$! is going on) So if you end up having no prompt on the console once the script exits, you have to re-run pyxiewps and kill it with CTRL-C when it's looking or APs, by doing that, you kill the Airodump process, terminate the Python program aaaaaaand... you have your prompt back. This way of resquing the prompt back is telling me that Python has issues terminating the ADump process and, if someone could give me some pro-tip on it, I would be fully grateful.

# Third party bugs 

[+] BE AWARE that some wireless devices are managed by the bcm4313 module. When Pyxiewps tries to bring the iterface up with:
	
        $ ifconfig <interface> up
	
the system crashes leaving the user no other option that bruteforcing a shutdown.
Check your wireless card and then it's module before running this script.
