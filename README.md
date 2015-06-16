# pyxiewps
Pyxiewps is a wireless attack tool writen in python to retrieve the WPS pin of any vulnerable AP in seconds.

It uses:
  Reaver: Reaver 1.5.2 mod by t6_x & DataHead & Soxrok2212 & Wiire & kib0rg
  Pixiewps: by wiire <wi7ire@gmail.com>
  Aircrack: http://www.aircrack-ng.org
  Macchanger: by Alvaro Lopez Ortega

There are already a bunch of tools, reaver included, that can attack an access point (AP) using the Pixie Dust vulnerability but I wanted to do something automatic, fast and user friendly, so here we are.

I also wrote this program to be used on the fly as I walk in the city. If the router is vulnerable, this script uses reaver and pixiewps to retrieve the AP password in, at least, 11 seconds. YUP! You get the WPA password of any vulnerable AP in 11 seconds using the fastest configuration.

It enumerates all the APs with active WPS, tries to get the PKE, PKR, E-NONCE, R-NONCE, AUTHKEY, HASH1 and 2 using the patched version of reaver, then passes all that information to pixiewps program so that it can retrieve the WPS pin, and finally runs reaver again with the pin that pixiewps found to get the AP WPA password.

Please report any bugs to pyxiewps@gmail.com
