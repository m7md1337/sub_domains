# sub_domains
### find subdomains by using archive.com and securitytrails.com with customizing the results
* install the requests library ``` pip install requests ```
* create a free account in securitytrails.com required email to activate the account then take the apikey to use the full tool
* if you do not have apikey the tools will use the results from archive only also if the apikey is wrong will use archive only
* example of using the script 
 ```
 python3 main.py -d github.com  -a LsNSr90eEHHZOf1blYLXR09fMmLjjNhx -o 80,http/443,https/8008,http/8080,http/8443,https -p 80,443,8008,8080,8443
```
* - d domain - a apikey 
* -o will save the data in url format like 80 for http will be http://url:80/blabla see ``` https://github.com/m7md1337/sub_domains/blob/main/custom-github.com-2022-05-15%2016:43:18.txt```
* it could be ftp://url:21 
* ex

 ```
 python3 main.py -d github.com  -o 80,http/443,https/8008,http/8080,http/8443,https -p 80,443,8008,8080,8443
```

without -p will scan the defuelt port 443,80
 ```
 python3 main.py -d github.com  
```
*
 ```
 python3 main.py -d github.com  -a LsNSr90eEHHZOf1blYLXR09fMmLjjNhx -p 80,443,8008,8080,8443
```
*
 ```
 python3 main.py -d github.com  -a LsNSr90eEHHZOf1blYLXR09fMmLjjNhx -o 80,http/443,https 
```
