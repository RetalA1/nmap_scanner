

import nmap

scanner = nmap.PortScanner()

print("Welcome, this is a simple nmap automation tool")                                        
print(r"""
      
 ________   _____ ______   ________  ________        ________  ________  ________  ________   ________   _______   ________     
|\   ___  \|\   _ \  _   \|\   __  \|\   __  \      |\   ____\|\   ____\|\   __  \|\   ___  \|\   ___  \|\  ___ \ |\   __  \    
\ \  \\ \  \ \  \\\__\ \  \ \  \|\  \ \  \|\  \     \ \  \___|\ \  \___|\ \  \|\  \ \  \\ \  \ \  \\ \  \ \   __/|\ \  \|\  \   
 \ \  \\ \  \ \  \\|__| \  \ \   __  \ \   ____\     \ \_____  \ \  \    \ \   __  \ \  \\ \  \ \  \\ \  \ \  \_|/_\ \   _  _\  
  \ \  \\ \  \ \  \    \ \  \ \  \ \  \ \  \___|      \|____|\  \ \  \____\ \  \ \  \ \  \\ \  \ \  \\ \  \ \  \_|\ \ \  \\  \| 
   \ \__\\ \__\ \__\    \ \__\ \__\ \__\ \__\           ____\_\  \ \_______\ \__\ \__\ \__\\ \__\ \__\\ \__\ \_______\ \__\\ _\ 
    \|__| \|__|\|__|     \|__|\|__|\|__|\|__|          |\_________\|_______|\|__|\|__|\|__| \|__|\|__| \|__|\|_______|\|__|\|__|
                                                       \|_________|                                                             
                                                                                                                                
                                                                                                                                """)
ip_addr = input("Please enter the IP address you want to scan: ")
print("The IP you entered is: " , ip_addr)
type(ip_addr)

resp = input("""\nPlease enter the type of scan you want to run
                 1)SYN ACK scanner
                 2)UDP scan
                 3)Comprehensive scan \n""")
print("You have selected option: ", resp)

if resp == '1':
    scan_type = "SYN ACK Scan"
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sS')
    print(scanner.scaninfo())
    print("IP Status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports: ", scanner[ip_addr]['tcp'].keys())
elif resp == '2':
    scan_type = "UDP Scan"
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sU')
    print(scanner.scaninfo())
    print("IP Status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    if 'udp' in scanner[ip_addr]:
        print("Open UDP Ports: ", scanner[ip_addr]['udp'].keys())
    else:
        print("No open UDP ports found.")
elif resp == '3':
    scan_type = "Comprehensive Scan"
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_addr, arguments='-p- -sS -sV -O -v')
    print(scanner.scaninfo())
    print("IP Status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    if 'tcp' in scanner[ip_addr]:
        print("Open TCP Ports: ", scanner[ip_addr]['tcp'].keys())
    else:
        print("No open TCP ports found.")
elif resp >= '4':
    print("Please enter a valid option")


import datetime, os

if not os.path.exists("logs"):
    os.makedirs("logs")

timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

log_data = []
log_data.append(f"Scan Timestamp: {timestamp}")
log_data.append(f"Target: {ip_addr}")
log_data.append(f"Scan Type: {scan_type}")
log_data.append("")

if 'tcp' in scanner[ip_addr] and scanner[ip_addr]['tcp']:
    log_data.append("Open TCP Ports:")
    for port, port_data in scanner[ip_addr]['tcp'].items():
        state = port_data.get('state', 'unknown')
        log_data.append(f"  {port} : {state}")

if 'udp' in scanner[ip_addr] and scanner[ip_addr]['udp']:
    log_data.append("\nOpen UDP Ports:")
    for port, port_data in scanner[ip_addr]['udp'].items():
        state = port_data.get('state', 'unknown')
        log_data.append(f"  {port} : {state}")

if ('tcp' not in scanner[ip_addr] or not scanner[ip_addr]['tcp']) and \
   ('udp' not in scanner[ip_addr] or not scanner[ip_addr]['udp']):
    log_data.append("No scanned ports found.")

filename = f"logs/scan_{ip_addr}_{timestamp}.txt"
with open(filename, "w") as f:
    f.write("\n".join(log_data))

print(f"\n[+] Scan saved to {filename}")

