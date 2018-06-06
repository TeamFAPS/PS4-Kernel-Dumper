# PS4 Kernel Dumper

Cross-compatible with PS4 on 4.05, 4.55, 5.01 and 5.05.

## USB dumping mode

Launch the payload. Connect an USB storage device. Follow the instructions on screen.

## Socket dumping mode

Compile with your PC's IP and choose the port you want (ex: 9023).

On PC you can do to listen:
	socat - tcp-listen:9023 > kernel_dump.bin

Then in a new cmd line, to send the payload:
	socat -u FILE:PS4-Kernel-Dumper.bin TCP:"PS4 IP":9020

You can then trim out the socket prints or you could adapt it with 2 sockets, one for dumping, another for logging.

## Building

To compile you have to use an updated payload sdk. For exemple: https://github.com/xvortex/ps4-payload-sdk

## Credits

* CelesteBlue for the rewriting (USB + cross FW compatibility)
* WildCard for his functional code
* Shadow for the copyout trick
* xvortex for the updated PS4 payload SDK
* CTurt for his PS4 payload SDK
* Specter for his Code Execution method and implementation
* qwertyoruiopz for his webkit and kernel exploits