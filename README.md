## NMAP Scanner
This Nmap scanner is a custom python-based nmap tool that is designed to perform automated scans, generate reports and parse results. After being prompted to enter an IP address, it allows you to run: a TCP SYD ACK scan, a UDP scan and a lightweight comprehensive scan.



1. SYN/ACK Scan runs using -sS -V that detects TCP open ports efficiently
2. UDP Scan runs using -sU -v which shows ports as opened|filtered
3. A lightweight comprehensive scan runs using -sU -V scanning the top 1024 UDP ports



All scans are saved to a log file such as "scan_results.txt" where each entry includes the type of scan, the timetsamp, discovered open ports and the target.