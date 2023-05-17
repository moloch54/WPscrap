# WPscrap
Fast and stealth WordPress scanner, no api-key, searching contributors  for auto-exploit module.  

# Installation  
```sh
git clone https://github.com/moloch54/WPscrap
```
```sh
cd WPscrap; pip3 install -r requirements.txt
```  
# Usage  
Updating Database:
```sh
python3 WPscrap.py --update
```  
Vulns detection:
```sh  
python3 WPscrap.py -L listofurls.txt
```
```sh
python3 WPscrap.py -L http://target.com
```
