# PS4 Kernel Dumper

Cross-compatible with PS4 on 3.50, 3.51, 3.55, 4.05, 4.55, 4.74, 5.00, 5.01, 5.03, 5.05 and 5.07.

## USB dumping mode

Launch the payload. Connect a USB storage device. Follow the instructions on the screen.

## Socket dumping mode

Compile with your PC's IP and choose the port you want (ex: 9023).

On PC you can do to listen:
	socat - tcp-listen:9023 > kernel_dump.bin

Then in a new cmd line, to send the payload:
	socat -u FILE:PS4-Kernel-Dumper.bin TCP:"PS4 IP":9020

You can then trim out the socket prints, or you could adapt it with 2 sockets, one for dumping, another for logging.

## Building

To compile you have to use an updated payload SDK. For example: https://github.com/xvortex/ps4-payload-sdk

## Credits

* SocraticBliss for maintainability, reboot and output filename timestamp
* CelesteBlue for rewriting (USB + cross FW compatibility)
* WildCard for functional code
* Shadow for copyout trick
* xvortex for updated PS4 payload SDK
* CTurt for PS4 payload SDK
* Specter for Code Execution method and implementation
* qwertyoruiopz for webkit and kernel exploits
