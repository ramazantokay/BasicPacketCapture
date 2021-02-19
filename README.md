BasicPacketCapture
====================
This application captures all trafic form a live network (like wireshark) and display every packets in detail.

Using the utility
-----------------

        Basic Usage:
            packet-capture [-h] [-v] [-l] [-n INTERFACE_NAME]"
        Options:
            -h|--help                                  : Displays this help message and exits
            -v|--version                               : Displays the current version and exits
            -l|--list                                  : Print the list of current interfaces and exits
            -n|--interface-name       INTERFACE_NAME   : Interface name that will be tracked

Example
-------

You can start to capture packets:
```shell
sudo ./packet-capture -n 'your_interface_name'
```

Important Notes
---------------
- Before compiling this application make sure you install PcapPlusPlus library. Otherwise the application won't compile
- This application should be run as 'sudo'
