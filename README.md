# WPscrap
Fast and stealth WordPress scanner, no api-key, no limitation.
Use the top-notch free open-source API www.wpvulnerability.net  
  
I'm looking for contributors helping me to dev an auto-exploit module.  

# Installation  
```sh
git clone https://github.com/moloch54/WPscrap; cd WPscrap; pip3 install -r requirements.txt  
```  
You can try if some issues:  
python3 -m pip install -r requirements.txt  

# Usage  
Update Database:
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
![WPscrap](https://github.com/moloch54/WPscrap/assets/123097488/92efc5c2-8552-459a-80d2-fa72cc722b92)
