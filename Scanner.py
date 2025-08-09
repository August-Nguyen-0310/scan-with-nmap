import nmap, sys
scanner = nmap.PortScanner()
ip_addr = input("Please enter the IP address to scan: ")

print (f"Scanning the IP address: {ip_addr}")

type(ip_addr)

resp = input("Please select the type of scan you want to perform:\n1. SYN Scan\n2. UDP Scan\n3. Comprehensive Scan\n4.Change IP Address\n5.Exit\n")
while True:
    if resp == '1':
        print("Nmap version: ", scanner.nmap_version())
        scanner.scan(ip_addr, '1-10', arguments='-f -v -sS')
        print(scanner.scaninfo())
        print('IP Status', scanner[ip_addr].state())
        print(scanner[ip_addr].all_protocols())
        print('Open Ports:', scanner[ip_addr]['tcp'].keys())
        break
    elif resp == '2':
        print("Nmap version: ", scanner.nmap_version())
        scanner.scan(ip_addr, '1-10', arguments='-f -v -sU')
        print(scanner.scaninfo())
        print('IP Status', scanner[ip_addr].state())
        print(scanner[ip_addr].all_protocols())
        print('Open Ports:', scanner[ip_addr]['udp'].keys())
        break
    elif resp == '3':
        print("Nmap version: ", scanner.nmap_version())
        scanner.scan(ip_addr, '1-10', arguments='-f -v -sS -sU -A -O')
        print(scanner.scaninfo())
        print('IP Status', scanner[ip_addr].state())
        print(scanner[ip_addr].all_protocols())
        print('Open TCP Ports:', scanner[ip_addr]['tcp'].keys())
        print('Open UDP Ports:', scanner[ip_addr]['udp'].keys())
        break
    elif resp == '4':
        ip_addr = input("Please enter the new IP address to scan: ")
        print(f"Scanning the new IP address: {ip_addr}")
    elif resp == '5':
        print("Exiting the scanner.")
        sys.exit()
    else:
        print("Invalid option. Please try again.")
        resp = input("Please select the type of scan you want to perform:\n1. SYN Scan\n2. UDP Scan\n3. Comprehensive Scan\n4.Change IP Address\n5.Exit\n")
