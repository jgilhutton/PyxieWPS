Pyxiewps Version 1.1
made by Juan Ignacio Gil-Hutton <pyxiewps@gmail.com>
Educational purposes only

CHANGELOG
=========

**Version 1.1:**

- Wash is no loger used to enumerate the WPS-active APs. Airodump is much faster providing a huge advantage when wardriving a zone.
- Pyxiewps now supports operative modes. This is much user-friendly, reducing the amount of arguments that must be given in the commandline.
**STATIC**, **DRIVE** and **WALK**.
- The program is optimized to be quick, and can now get the AP password in 9 seconds.
- Pyxiewps must run in a console with more than 110 columns to avoid problems in the Airodump parser. The minumum screen size where the script
  was tested was 1024x600. To avoid problems maximize the window.
- Macchanger is no longer used. Didn't help at all bypassing the AP blockout.
- User can now provide a max amount of targets to attack.
- When channel is provided in the commandline (argument), Airodump time is changed to 1 second to speed up the enumerating process.
- Filename isn't mandatory anymore when giving the '-o' argument in the commandline. The default filename is data.txt.
- User can now filter the APs by RSSI.
- Pixiewps won't spend more than 2 seconds trying to get the WPS pin. Sometimes it reached 13 seconds blowing up all the program purpose of being fast.
- By default, the program will blacklist any AP that was attacked and return negative results.
- When user input is needed, index errors will be managed. <-- EPIC fail in previous version.

If you need any help don't forget to run the program with '-h' flag.

jgilhutton
