# sub_domains v0.2
### find subdomains by using web.archive.org and securitytrails.com with customizing the results
* install the requests library ``` pip install requests ```
* create a free account in securitytrails.com required email to activate the account then take the apikey to use the full tool
* if you do not have apikey the tools will use the results from archive only also if the apikey is wrong will use archive only
* example of using the script 
 ```
 python3 main.py -d github.com -a LsNSr90eEHHZOf1blYLXR09fMmLjjNhxf -o 80,http/443,https/8008,http/8080,http/8443,https/http,8000 -p 80,443,8008,8080,8443,8000 -l filehavehosts.txt -e ends.txt
```
* -d domain
* -a apikey 
* -o will save the data in url format like 80 for http will be http://url:80/blabla see ``` https://github.com/m7md1337/sub_domains/blob/main/custom-github.com-2022-05-15%2016:43:18.txt```
* -l list of subdomains to test it 
* -e to test the custom urls with endpoints or paths from text file !Note this option work with -o 
 ![alt text](https://raw.githubusercontent.com/m7md1337/sub_domains/main/images/0.2.png)

* it could be ftp://url:21 
* ex

 ```
 python3 main.py -d github.com  -o 80,http/443,https/8008,http/8080,http/8443,https -p 80,443,8008,8080,8443
```

without -p will scan the defuelt port 443,80
 ```
 python3 main.py -d github.com  
```
 ```
 python3 main.py -d github.com  -a LsNSr90eEHHZOf1blYLXR09fMmLjjNhx -p 80,443,8008,8080,8443
```
 ```
 python3 main.py -d github.com  -a LsNSr90eEHHZOf1blYLXR09fMmLjjNhx -o 80,http/443,https 
```

