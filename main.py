import requests
import re
import socket
import json
import sys
import argparse
import concurrent.futures
import datetime

customelivedomains = []  # if outdict exists will save the data here
listdomains = []  # lists from security and archive
livedomains = []  # live domain from port_scan
outdict = {}  # option -o to insert port with value in dict ex  -o 80/http will > {"80":"http"}


def parser_error(errmsg):
    print("an error occurred> Usage: python " + sys.argv[0] + " [Options] use -h for help")
    sys.exit()


def parse_args():
    # parse the arguments
    parser = argparse.ArgumentParser(epilog='\tExample: \r\npython ' + sys.argv[0] + " -d google.com")
    parser.error = parser_error
    parser._optionals.title = "OPTIONS"
    parser.add_argument('-d', '--domain', help="Domain name to ex google.com", required=True)
    parser.add_argument('-p', '--ports', help='Scan the found subdomains against specified tcp ports', default="80,443")
    parser.add_argument('-a', '--apikey', help='api key use for securitytrails', )
    parser.add_argument('-o', '--output', help='customizing the result 80,http/443,https use slash between the port,protocol')
    return parser.parse_args()


def port_scan(host, ports):
    global livedomains, customelivedomains
    openports = []
    for port in ports:  # port in array
        try:  # try if alive continue else raise an error without save into livedomains
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            result = s.connect_ex((host, int(port)))
            if result == 0:  # if open
                openports.append(port)  # insert into livedomains
                if outdict:  # if users use option -o
                    if outdict[port]:  # if the port key has value will save into  customelivedomains
                        customelivedomains.append("{}://{}:{}".format(outdict[port], host, port))
                livedomains.append("{}:{}".format(host,
                                                  port))  # from if result == 0: direct to here if none of above condition executed
            s.close()
        except Exception:
            s.close()  # may occur an error before line 45 so ensure the socket is close
            pass
    if len(openports) > 0:
        print("{}- Found open ports:{}".format(host, ', '.join(
            str(v) for v in openports)))  # loop for data in array with modify the port to str


# add to list
def addtodomains(domain):
    global listdomains
    try: # check if value in list or not if not will raise error so by use except , handle the error to add domain into the list else pass
        b = listdomains.index(domain.split(":")[0])
    except ValueError:
        listdomains.append(domain.split(":")[0])
    else:
        pass


### regex the uls in response from archive to be xxx.com
def byarchive(domain):
    try:
        regexurl = r'(?<=\://)(.*?)(?=\/)'
        url = "https://web.archive.org/cdx/search/cdx?url=*.{}&fl=original&collapse=urlkey".format(domain)
        res = requests.get(url)
        for url in res.text.split("\n"):
            rr = re.findall(regexurl, url + "/")
            addtodomains(rr[0])
    except Exception as e:
        pass

# response in json for loop in the key subdomains and send the data to addtodomains()
def bysecuritytrails(domain, apikey):
    re = requests.get("https://api.securitytrails.com/v1/ping", headers={"APIKEY": apikey})
    if re.status_code != 200:
        print("make sure you're use valid securitytrails api key the tools work without securitytrails api result")
        return ""
    try:
        url = 'https://api.securitytrails.com/v1/domain/{}/subdomains?children_only=false&include_inactive=true'.format(
            domain)
        res = requests.get(url, headers={"APIKEY": apikey})
        for xx in json.loads(res.content)["subdomains"]:
            addtodomains(xx + "." + domain)
    except Exception as e:
        pass


def main(): # define args
    args = parse_args()
    domain = args.domain
    apikey = args.apikey
    savefile = args.output
    ports = args.ports
    ports = ports.split(',')
    print("the result may take a time")
    fiee = "result will save in file {domain}-data.txt in format host:port to customize the result use -o methode" # if -o option not use will be
    try:
        if savefile:
            fiee = "result will in file {domain}-data.txt" # if -o option used
            dd = [x.split(",") for x in savefile.split("/")] # split the input
            for xx in dd:
                outdict[xx[0]] = xx[1] # add to outdict
    except Exception:
        parser_error("error")
    print(fiee)
    if apikey != None:
        bysecuritytrails(domain, apikey)
        byarchive(domain)
    else:
        byarchive(domain)
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        domains = {executor.submit(port_scan, subdomains, ports): subdomains for subdomains in listdomains}
        for future in concurrent.futures.as_completed(domains):
            subdomins = domains[future]
            try:
                data = future.result()
            except Exception as exc:
                pass
    if savefile:
        if customelivedomains:
            name = "custom-{}-{}.txt".format(domain, datetime.datetime.now().strftime("%Y-%m-%d+%H:%M:%S"))
            file = open(name, "+a")
            for xx in customelivedomains:
                file.write(xx + "\n")
            file.close()
            print("custom file saved with name: " + name)
    name = "{}-{}.txt".format(domain, datetime.datetime.now().strftime("%Y-%m-%d+%H:%M:%S"))
    if livedomains:
        file = open(name, "+a")
        for xx in livedomains:
            file.write(xx + "\n")
        file.close()
        print("valid domain saved with name: " + name)
    if not livedomains and not customelivedomains:
        print("no data found for : {}".format(domain))

if __name__ == '__main__':
    main()
