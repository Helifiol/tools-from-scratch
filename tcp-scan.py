import optparse
import socket
import threading

lock = threading.Lock()
results = []
threads = []

def main():
    parser = optparse.OptionParser('Usage %prog -H ' +\
                                '<target host> -p <target port>')

    parser.add_option('-H', dest='tgtHost', type='string', \
                    help='specify target host')
    parser.add_option('-p', dest="tgtPort", type='string', \
                    help='sepcify target port[s] seperated by comma')
    parser.add_option('-sn', dest='ping_scan', type='boolean', \
                    help='Enable ping scan')

    (options, args) = parser.parse_args()
    tgtHost = options.tgtHost
    tgtPort = str(options.tgtPort)
    ping_scan = options.ping_scan
    print(ping_scan)

    if(tgtPort == None) | (tgtHost[0] == None):
        print(parser.usage)
        exit(0)
    tgtPort = tgtPort.split(',')
    portScan(tgtHost, tgtPort)

def connScan(tgtHost, tgtPort):
    try:
        connSkt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connSkt.connect((tgtHost, int(tgtPort)))
        lock.acquire()
        results.append('[+] %d/tcp open\n'% int(tgtPort))
        # print('[+] %d/tcp open\n'% int(tgtPort))
    except:
        lock.acquire()
        results.append("[-] %d/tcp closed\n"% int(tgtPort))
        # print("[-] %d/tcp closed\n"% int(tgtPort))
    finally:
        lock.release()
        connSkt.close()

def portScan(tgtHost, tgtPorts):
    try:
        tgtIP = socket.gethostbyname(tgtHost)
    except:
        print("[-] Cannot resolve '%s' : unknown host"%tgtHost)
        return
    try:
        tgtName = socket.gethostbyaddr(tgtIP)[0]
        print("\n[+] Scan Result for: " + tgtName + "\n")
    except:
        print("\n[+] Scan Result for: " + tgtIP + "\n")
    socket.setdefaulttimeout(1)
    for tgtPort in tgtPorts:
        
        print('Scanning port: ' + str(tgtPort))
        
        t = threading.Thread(target=connScan, args=(tgtIP, tgtPort))
        t.start()
        threads.append(t)
        
        # connScan(tgtHost, int(tgtPort))
    for t in threads:
        # print(t)
        t.join()

    for result in results:
        print(result)

if __name__ == "__main__":
    main()