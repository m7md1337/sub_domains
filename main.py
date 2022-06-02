import requests
import re
import socket
import json
import sys
import argparse
import concurrent.futures
import datetime
import random
import art
from lxml.html import fromstring
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

customelivedomains = []  # if outdict exists will save the data here
listdomains = []  # lists from security and archive
livedomains = []  # live domain from port_scan
outdict = {}  # option -o to insert port with value in dict ex  -o 80/http will > {"80":"http"}
statuss = []
class myexcgetout(Exception):
    pass


class bcolors:

    def conv(id):
        if str(id)[:1] == "2":# 2XX return green
            return '\033[92m'
        elif str(id)[:1] == "3": # 3XX return blue
            return '\033[94m'
        elif str(id)[:1] == "4": # 4XX return Magenta
            return '\033[35m'
        elif str(id)[:1] == "5": # 5XX return red
            return '\033[91m'


    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    def1 =  '\033[49m'
def random_char(y):
    return ''.join(random.choice("!@#$%^&*()_+{}<>?\"'") for x in range(y))

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
    parser.add_argument('-l', '--listOfHost', help='add the list of subdomains to test function check the port valid if add them to the text file, the file format should be host.com in each line  ', )
    parser.add_argument('-o', '--output', help='customizing the result 80,http/443,https use slash between the port,protocol')
    parser.add_argument('-t', '--thread',help='default thread 80 ',type=int,default=80)
    parser.add_argument('-e', '--endpoints', help='this option will check the urls with small endpoints input should be file text ')
    parser.add_argument('-f', '--followtheredirect', help='follow the redirect default True ', type=int, default=True)
    parser.add_argument('-s', '--statuss', help='show the data if status in defaults 200,204,302,301,307,401,403,405,500 ', type=int, default=[200,204,302,301,307,401,403,405,500])
    return parser.parse_args()

def thee(nameoffunc, ports ,fileoflistorlist,thread=80):
    with concurrent.futures.ThreadPoolExecutor(max_workers=thread) as executor:
        domains = {executor.submit(nameoffunc, subdomains, ports): subdomains for subdomains in fileoflistorlist}
        for future in concurrent.futures.as_completed(domains):
            subdomins = domains[future]
            try:
                data = future.result()
            except Exception as exc:
                pass


def thee1(nameoffunc,url ,fileoflistorlist,followtheredirect):
    with concurrent.futures.ThreadPoolExecutor(max_workers=80) as executor:
        domains = {executor.submit(nameoffunc, url, subdomains, followtheredirect): subdomains for subdomains in fileoflistorlist}
        try:
                def too():
                    for future in concurrent.futures.as_completed(domains):
                        subdomins = domains[future]
                        #print(url+"/"+subdomins)
                        print(f"{bcolors.def1}",">>> trying {}% ".format(subdomins[:10]), end='\r\r', flush=True)
                        try:
                            data = future.result()
                            print("".join(map(str, data)),sep="")
                        except Exception as e:
                            #print(str(e))
                            pass
                too()
        except KeyboardInterrupt:
                print(f"{bcolors.def1}\nwait... {bcolors.ENDC}")
                cc = input("\nplease enter first letter to move_to_next_url (m) kill_the_script (k) |||XXX|||no continue option for now|||XXX|||: ")
                if cc == "m":
                    print("moving ....")
                    executor.shutdown(cancel_futures=True)
                if cc == "k":
                    print("killing the script ....")
                    executor.shutdown(cancel_futures=True)
                    raise myexcgetout()
#                if cc == "c":
#                    return ""

def ss(url, endpoints, follow):
        if endpoints[0] != "/":
            endpoints = "/" + endpoints
        try:
            re = requests.get(url + endpoints, verify=False, timeout=5, allow_redirects=follow)
            if re.status_code in statuss:
                if len(re.text) != 0:
                    tree = fromstring(re.content)
                    if tree.findtext('.//title') is not None:
                        return f"{bcolors.conv(re.status_code)}", "originUrl: " + url + endpoints + " ,TheRedirectUrl: " + re.url if re.history else "URl: " + re.url, " ,titel: ", tree.findtext('.//title').replace("\n", "").replace("\r",""), " ,status: ", re.status_code, " ,redirect to :" + re.headers['Location'] + {bcolors.ENDC} if "location" in re.headers else f"{bcolors.ENDC} "
                    else:
                        return f"{bcolors.conv(re.status_code)}", "from originUrl: " + url + endpoints + " ,To TheRedirectUrl: " + re.url if re.history else "URl: " + re.url, " ,status: ", re.status_code, " ,redirect to :" +re.headers['Location'] + {bcolors.ENDC} if "location" in re.headers else f"{bcolors.ENDC} "
                else:
                    return f"{bcolors.conv(re.status_code)}", "originUrl: " + url + endpoints + " ,TheRedirectUrl: " + re.url if re.history else "URl: " + re.url, " ,status: ", re.status_code, " ,redirect to :" + re.headers['Location'] + {bcolors.ENDC} if "location" in re.headers else f"{bcolors.ENDC} "
            else:
                pass
        except Exception as e:
            # print(str(e))
            pass

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
                    if outdict[str(port)]:  # if the port key has value will save into  customelivedomains
                        customelivedomains.append("{}://{}:{}".format(outdict[str(port)], host, port))
                livedomains.append("{}:{}".format(host,
                                                  port))  # from if result == 0: direct to here if none of above condition executed
            s.close()
        except Exception:
            s.close()  # may occur an error before line 45 so ensure the socket is close
            pass
    if len(openports) > 0:
        print(f"{bcolors.OKBLUE}","{} - Found open ports: ".format(host),f"{bcolors.FAIL}","{}".format(', '.join(str(v) for v in openports)) ,f"{bcolors.ENDC}",sep="")  # loop for data in array with modify the port to str


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
        print(f"{bcolors.WARNING}","error in api key for securitytrails : make sure you're use valid securitytrails api key the tools work without securitytrails api result",f"{bcolors.ENDC}",sep="")
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
    global statuss
    args = parse_args()
    domain = args.domain
    apikey = args.apikey
    savefile = args.output
    ports = args.ports
    filefrominput = args.listOfHost
    threads = args.thread
    endpoints = args.endpoints
    followtheredirect = args.followtheredirect
    statuss = args.statuss
    ports = ports.split(',')
    print(f"{bcolors.OKBLUE}the result may take a time",f"{bcolors.ENDC}",sep="")
    fiee = "result will save in file {domain}-data.txt in format host:port to customize the result use -o methode" # if -o option not use will be
    if filefrominput:
        try:
            d = open(filefrominput, "r")
            for xx in d.read().splitlines():
                listdomains.append(xx)
        except Exception:
            exit("error : no file called {}".format(filefrominput))
    try:
        if savefile:
            fiee = "result will in file {domain}-data.txt" # if -o option used
            dd = [x.split(",") for x in savefile.split("/")] # split the input
            for xx in dd:
                outdict[xx[0]] = xx[1] # add to outdict
    except Exception:
        exit("error")
    print(f"{bcolors.OKBLUE}",fiee,f"{bcolors.ENDC}",sep="")
    if apikey != None:
        bysecuritytrails(domain, apikey)
        byarchive(domain)
    else:
        byarchive(domain)
    listdomains.sort()
    thee(port_scan,ports,listdomains,thread=threads)
    if savefile:
        if customelivedomains:
            customelivedomains.sort()
            name = "custom-{}-{}.txt".format(domain, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            file = open(name, "+a")
            for xx in customelivedomains:
                file.write(xx + "\n")
            file.close()
            print(f"{bcolors.WARNING}custom file saved with name: " + name,f"{bcolors.ENDC}",sep="")
    name = "{}-{}.txt".format(domain, datetime.datetime.now().strftime("%Y-%m-%d+%H:%M:%S"))
    if livedomains:
        livedomains.sort()
        file = open(name, "+a")
        for xx in livedomains:
            file.write(xx + "\n")
        file.close()
        print(f"{bcolors.WARNING}valid domain saved with name: " + name,sep="")
    if not livedomains and not customelivedomains:
        print(f"{bcolors.FAIL}","no data found for : {}".format(domain),f"{bcolors.ENDC}",sep="")
    if endpoints and customelivedomains:
        try:
            ee = open(endpoints, "+r").read().splitlines()
        except Exception:
            exit("error : no file called {}".format(filefrominput))
        input(f"{bcolors.OKBLUE}[to jump to next url enter Ctrl + c , to stop enter ctrl + c two times  ] -- please enter Enter to start {bcolors.ENDC}")
        for xx in customelivedomains:
            try:
                print(f"{bcolors.def1}starting on url : " + xx + "\n "f"{bcolors.ENDC}")
                thee1(ss, xx, ee,followtheredirect)
            except myexcgetout:
                print("see you soon")
                break
if __name__ == '__main__':
    # print(f"{bcolors.OKBLUE}")
    # print(random_char(32)+" "*20+random_char(38))
    # print(random_char(32) + " " * 20 + random_char(39))
    # print(random_char(32) + " " * 20 + random_char(40))
    # print(random_char(32) + " " * 20 + random_char(12)+" "*20+random_char(12))
    # print(random_char(12) + " " * 40 + random_char(12) + " " * 20 + random_char(11))
    # print(random_char(12) + " " * 40 + random_char(12) + " " * 20 + random_char(12))
    # print(random_char(12) + " " * 40 + random_char(12) + " " * 20 + random_char(11))
    # print(random_char(12) + " " * 40 + random_char(12) + " " * 20 + random_char(11))
    # print(random_char(12) + " " * 40 + random_char(12) + " " * 20 + random_char(11))
    # print(random_char(12) + " " * 40 + random_char(12) + " " * 20 + random_char(11))
    # print(random_char(12) + " " * 40 + random_char(12) + " " * 20 + random_char(11))
    # print(random_char(12) + " " * 40 + random_char(12) + " " * 20 + random_char(11))
    # print(random_char(12) + " " * 40 + random_char(12) + " " * 20 + random_char(11))
    # print(random_char(32) + " " * 20 + random_char(12) + " " * 20 + random_char(11))
    # print(random_char(32) + " " * 20 + random_char(12) + " " * 20 + random_char(11))
    # print(" "*20+random_char(12) + " " * 20 + random_char(12) + " " * 20 + random_char(11))
    # print(" " * 20 + random_char(12) + " " * 20 + random_char(12) + " " * 20 + random_char(11))
    # print(" " * 20 + random_char(12) + " " * 20 + random_char(12) + " " * 20 + random_char(11))
    # print(" " * 20 + random_char(12) + " " * 20 + random_char(12) + " " * 20 + random_char(11))
    # print(" " * 20 + random_char(12) + " " * 20 + random_char(12) + " " * 20 + random_char(11))
    # print(" " * 20 + random_char(12) + " " * 20 + random_char(12) + " " * 20 + random_char(11))
    # print(" " * 20 + random_char(12) + " " * 20 + random_char(12) + " " * 20 + random_char(11))
    # print(" " * 20 + random_char(12) + " " * 20 + random_char(12) + " " * 20 + random_char(10))
    # print(" " * 20 + random_char(12) + " " * 20 + random_char(12) + " " * 20 + random_char(11))
    # print(random_char(32) + " " * 20 + random_char(12)+" "*20+random_char(12))
    # print(random_char(32) + " " * 20 + random_char(40))
    # print(random_char(32) + " " * 20 + random_char(39))
    # print(random_char(32)+" "*20+random_char(38))
    # print(f"{bcolors.ENDC}")
    print(f"{bcolors.OKBLUE}")
    print(art.text2art("sub_DOMAINS","rand"))
    print(f"{bcolors.ENDC}")

    main()
