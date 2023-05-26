#!/usr/bin/python3 -u
from concurrent.futures import ThreadPoolExecutor
import time
import os
import argparse
import json
import datetime
import requests
import glob
import regex as re
import time
from colorama import Fore,Style, init
import random
import git
import shutil

VERSION = "1.1"

white_underscore = "\033[4;37m"

red = Fore.RED + Style.BRIGHT
green = Fore.GREEN + Style.BRIGHT
yellow = Fore.YELLOW + Style.BRIGHT
blue = Fore.BLUE + Style.BRIGHT
white = Fore.WHITE + Style.BRIGHT
reset = Style.RESET_ALL

nb_core_update = 0
nb_themes_update = 0
nb_plugins_update = 0
nb_files_2_update = 0
update_error = 0
updated_files = 0

header = ['Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
			'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
			'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:53.0) Gecko/20100101 Firefox/53.0',
			'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0; Trident/5.0)',
			'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; Trident/6.0; MDDCJS)'
			'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14393'
			'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)'
			]
headers = {
	'User-Agent': random.choice(header)
	}

def printf(message,color):
		print(color+"[*]"+blue+message+white)

def parse_arg():
	parser = argparse.ArgumentParser(description="Fast and stealth WordPress scanner")
	parser.add_argument("-L", help="list of url")
	parser.add_argument("-v", action="store_true", help="version")
	parser.add_argument("-o", help="output file")
	parser.add_argument("--update",action="store_true", help="updating DB")

	args = parser.parse_args()	
	#print(args) 
	return args

def check_core_vulns(core_version):
	# core
	with open(f'vulnDatabase/coreVuln/{core_version}', 'r') as f:
		#f.read()
		#if f.read()=="":
		#	return []
		#exit()
		try:
			vuln = json.load(f)
		except:
			return []
	tab_vuln=[]
	v = vuln['data']['vulnerability']
	#print(len(v))
	if v is not None:
		for i in range(len(v)):
			try:
				cve = v[i]['source'][0]['id'] 
				description = v[i]['source'][0]['description']
				link = v[i]['source'][0]['link']
				date = v[i]['source'][0]['date']
				severity = v[i]['impact']['cvss']['severity']
				privileges = v[i]['impact']['cvss']['pr']
				name =v[i]['impact']['cwe'][0]['name']
				
				if (severity in ['c','h']) and (privileges in ['n','l']) and 'CVE' in cve:
				#if (severity == 'h' or severity == 'c'):

					dict_vuln={}
					dict_vuln['name']= name.replace("&lt;","<")
					dict_vuln['cve']= cve
					dict_vuln['link'] = link
					dict_vuln['privileges'] = privileges
					dict_vuln['severity'] = severity
					tab_vuln.append(dict_vuln)
					#print(link)
			except:
				pass
		return tab_vuln
	else:
		return []


def check_theme_vulns(theme, theme_version):
	with open(f'vulnDatabase/themesVuln/{theme}', 'r') as f:
		#a=f.read()
		#if a=="":
		#	return []
		try:
			vuln = json.load(f)
		except:
			return []
	#print("innnnnn",vuln)
	tab_vuln=[]

	v = vuln['data']['vulnerability']
	#print(v)
	if v is not None:
		for i in range(len(v)):
			try:
				cve = v[i]['source'][0]['id'] 
				description = v[i]['source'][0]['description']
				link = v[i]['source'][0]['link']
				date = v[i]['source'][0]['date']
				min_version = v[i]['operator']['min_version']
				if min_version in [None,'','null']:
					min_version ="0"
				max_version = v[i]['operator']['max_version']
				if max_version in [None,'','null']:
					max_version="1000000"
				#print(min_version,theme_version,max_version)
				severity = v[i]['impact']['cvss']['severity']
				privileges = v[i]['impact']['cvss']['pr']
				name =v[i]['impact']['cwe'][0]['name']
				
				if (severity in ['c','h']) and (privileges in ['n','l']) and 'CVE' in cve and min_version <= plugin_version < max_version:
					dict_vuln={}
					dict_vuln['name']= name.replace("&lt;","<")
					dict_vuln['cve']= cve
					dict_vuln['link'] = link
					dict_vuln['privileges'] = privileges
					dict_vuln['severity'] = severity
					tab_vuln.append(dict_vuln)
			except:
				pass
		return tab_vuln
	else:
		return []



def check_plugin_vulns(plugin, plugin_version):

	with open(f'vulnDatabase/pluginsVuln/{plugin}', 'r') as f:
		a=f.read()
		try:
			vuln = json.loads(a)
		except:
			return []

	tab_vuln=[]

	v = vuln['data']['vulnerability']
	#print(v)
	if v is not None:
		for i in range(len(v)):
			try:
				cve = v[i]['source'][0]['id'] 
				description = v[i]['source'][0]['description']
				link = v[i]['source'][0]['link']
				date = v[i]['source'][0]['date']
				min_version = v[i]['operator']['min_version']
				max_version = v[i]['operator']['max_version']

				if min_version in [None,'','null']:
					min_version ="0"
				max_version = v[i]['operator']['max_version']
				if max_version in [None,'','null']:
					max_version="1000000" 

				if 'cvss' in v[i]['impact'] and 'cwe' in v[i]['impact']: 
					severity = v[i]['impact']['cvss']['severity']
					privileges = v[i]['impact']['cvss']['pr']
					#name =v[i]['impact']['cwe'][0]['name']
					name = v[i]['source'][1]['name']

					if (severity in ['c','h']) and (privileges in ['n','l']) and 'CVE' in cve and min_version <= plugin_version < max_version:
					#if (severity == 'h' or severity =='c') and 'CVE' in cve:
						dict_vuln={}
						dict_vuln['name']= name.replace("&lt;","<")
						dict_vuln['cve']= cve
						dict_vuln['link'] = link
						dict_vuln['privileges'] = privileges
						dict_vuln['severity'] = severity
						tab_vuln.append(dict_vuln)
			except:
				pass
		return tab_vuln
	else:
		return []

def show_vulns(tabdict_vulns, tabulation=1):
	for dict_vuln in tabdict_vulns:
		priv=""
		if dict_vuln['privileges'] == 'n':
			priv = 'UNAUTHENTICATED'
		if dict_vuln['severity'] == 'c' and priv =='UNAUTHENTICATED':
			priv = white +"[ " + red+ priv + white + " ]"
			cve = white + "[ " + red + dict_vuln['cve'] + white + " ]"
			print("\t"*tabulation, priv.ljust(46),cve.ljust(46), white+dict_vuln['link'] ,"\t"+dict_vuln['name'])
	for dict_vuln in tabdict_vulns:
		priv=""
		if dict_vuln['privileges'] == 'l':
			priv = 'AUTHENTICATED'
		if dict_vuln['severity'] == 'c' and priv =='AUTHENTICATED':
			priv = white +"[ " + yellow + priv + white + " ]  "
			cve = white + "[ " + red + dict_vuln['cve'] + white + " ]"
			print("\t"*tabulation, priv.ljust(46), cve.ljust(46),white+dict_vuln['link'], "\t"+dict_vuln['name'])

	for dict_vuln in tabdict_vulns:
		priv=""
		if dict_vuln['privileges'] == 'n':
			priv = 'UNAUTHENTICATED'
		if dict_vuln['severity'] == 'h' and priv =='UNAUTHENTICATED':
			priv = white +"[ " + red + priv + white + " ]"
			cve = white + "[ " + yellow + dict_vuln['cve'] + white + " ]"

			print("\t"*tabulation, priv.ljust(46), cve.ljust(46),white+dict_vuln['link'],"\t"+dict_vuln['name'])
	for dict_vuln in tabdict_vulns:
		priv=""
		if dict_vuln['privileges'] == 'l':
			priv = 'AUTHENTICATED'
		if dict_vuln['severity'] == 'h' and priv =='AUTHENTICATED':
			priv = white +"[ " + yellow + priv + white + " ]  "
			cve = white + "[ " + yellow + dict_vuln['cve'] + white + " ]"
			print("\t"*tabulation, priv.ljust(46),cve.ljust(46),white+dict_vuln['link'],"\t"+dict_vuln['name'])

def update_core(file, nb_files_2_update, session, headers):
	global update_error
	global updated_files
	try:
		with session.get(f'https://www.wpvulnerability.net/core/{file}', headers=headers, timeout = 1) as response:
			if response.status_code == 200:
				with open(f'vulnDatabase/coreVuln/{file}', 'wb') as file:
					file.write(response.content)
					updated_files += 1
					print(f"\r{updated_files}/{nb_files_2_update}", end="")
			else:
				update_error += 1
	except:
		update_error += 1

def update_themes(file, nb_files_2_update, session, headers):
	global update_error
	global updated_files

	try:
		with session.get(f'https://www.wpvulnerability.net/theme/{file}', headers=headers, timeout = 1) as response:
			if response.status_code == 200:
				with open(f'vulnDatabase/themesVuln/{file}', 'wb') as file:
					file.write(response.content)
					updated_files += 1
					print(f"\r{updated_files}/{nb_files_2_update}", end="")
			else:
				update_error += 1
	except:
		update_error += 1

def update_plugins(file, nb_files_2_update, session, headers):
	global update_error
	global updated_files

	try:
		with session.get(f'https://www.wpvulnerability.net/plugin/{file}', headers=headers, timeout = 1) as response:
			if response.status_code == 200:
				with open(f'vulnDatabase/pluginsVuln/{file}', 'wb') as file:
					file.write(response.content)
					updated_files += 1
					print(f"\r{updated_files}/{nb_files_2_update}", end="")
			else:
				update_error += 1
	except:
		update_error += 1


def update():
	global updated_files
	global update_error
	updated_files =0
	update_error = 0

	file_tab = []

	printf(" Cloning repo",green)
	# Cloner le référentiel GitHub
	git.Repo.clone_from('https://github.com/moloch54/WPscrap', 'temp_repo')

	printf(" updating WPscrap.py", green)
	# copie de WPscrap.py
	shutil.copyfile("temp_repo/WPscrap.py", "./WPscrap.py")

	printf(" updating exploits", green)
	# Copier les fichiers du dossier "toto" dans le répertoire courant
	shutil.copytree('temp_repo/vulnDatabase/exploits', "vulnDatabase/exploits", dirs_exist_ok=True)

	# Supprimer le référentiel cloné
	shutil.rmtree('temp_repo')


	printf(" updating core vulns",green)

	# building arguments
	for file in os.listdir("vulnDatabase/coreVuln"):
		file_tab.append(file)
	nb_file=len(file_tab)

	# multi-thread
	with ThreadPoolExecutor(max_workers=5) as executor:
		with requests.session() as session:
			executor.map(update_core, file_tab, [nb_file]*nb_file, [session]*nb_file, [headers]*nb_file)
			executor.shutdown(wait=True)
			#for future in futures:
			#	print(future)

	file_tab = []
	updated_files = 0
	print()
	printf(" updating themes vulns",green)

	# building arguments	
	for file in os.listdir("vulnDatabase/themesVuln"):
		file_tab.append(file)
	nb_file=len(file_tab)

	# multi-thread 
	with ThreadPoolExecutor(max_workers=10) as executor:
		with requests.session() as session:
			executor.map(update_themes, file_tab, [nb_file]*nb_file, [session]*nb_file, [headers]*nb_file)
			executor.shutdown(wait=True)
			#for future in futures:
			#	print(future)

	file_tab = []
	updated_files = 0

	print()
	printf(" updating plugins vulns",green)

	# building arguments	
	for file in os.listdir("vulnDatabase/pluginsVuln"):
		file_tab.append(file)
	nb_file=len(file_tab)

	# multi-thread 
	with ThreadPoolExecutor(max_workers=10) as executor:
		with requests.session() as session:
			executor.map(update_plugins, file_tab, [nb_file]*nb_file, [session]*nb_file, [headers]*nb_file)
			executor.shutdown(wait=True)
			#for future in futures:
			#	print(future)

	if not update_error:
		print()
		printf(" no update error", green)
	else:
		print()
		printf(f" update error, {update_error} file(s) not updated",red)


def get_spider(name, url , regex, headers, session):
	try:
		with session.get(url, headers=headers, timeout=3) as response:
			match = re.search(rf"{regex}", response.text)
			#print(response.text)
			if match:
				return (name, match.group(1))
	except:
		return None
	return None

def extract_plugins_with_template(curl_result, regex, nb_group, template_name):
	match = re.findall(rf"{regex}", curl_result)
	for i in range(len(match)):
		if type(match[i]) is tuple:
			match[i] = (template_name, match[i][1])
		else:
			match[i] = template_name
	return match

def get_users_API(users):
	users=json.loads(users)
	author_set = {}
	for user in users:
		author_set[user["id"]] = user["slug"]
	return author_set

def get_users_feed(xml):
	regex=r'<dc:creator>[\n\s]*<\!\[CDATA\[([\w\s\-]+)\]'
	match = re.findall(rf"{regex}", xml)
	return list(set(match))


#
# script start
#

args=parse_arg()
print()

if args.v:
	print(f"WPscrap version {VERSION}")
	exit()

if args.update:
	update()
	with open("vulnDatabase/lastUpdate.txt","w") as f:
		last=str(datetime.date.today())
		f.write(last)
	exit()

# check the last update
with open("vulnDatabase/lastUpdate.txt","r") as f:
	last=f.read()
if last=="\n":
	with open("vulnDatabase/lastUpdate.txt","w") as f:
		last=str(datetime.date.today())
		f.write(last)
		#print(last)
last=last.replace("\n","")
last=last.split("-")
last=datetime.date(int(last[0]),int(last[1]),int(last[2]))
delta=datetime.date.today() - last
if delta.days > 7:
	if input("Updating Vuln Database? (Y/n):") in ['', '\n', 'Y', 'yes', 'YES', 'y', 'Yes']:
		update()
		with open("vulnDatabase/lastUpdate.txt","w") as f:
			last=str(datetime.date.today())
			f.write(last)


for file_path in glob.glob('/tmp/*.txt'):
	os.remove(file_path)

# loading core_versions
all_core_version_tab = os.listdir(f'vulnDatabase/coreVuln/')

# loading themes:
all_themes_tab = os.listdir(f'vulnDatabase/themesVuln/')

# on charge les plugins:
all_plugins_tab = os.listdir(f'vulnDatabase/pluginsVuln/')


# loading templates (regex) for plugins detections
templates_tab=[]
for file in os.listdir("vulnDatabase/templates/"):
	with open(f"vulnDatabase/templates/{file}","r") as f:
		template=f.readlines()
		templates_tab.append(template)

# loading spiders for plugins readme.txt
spiders_tab=[]
for file in os.listdir("vulnDatabase/spiders/"):
	with open(f"vulnDatabase/spiders/{file}","r") as f:
		spider=f.readlines()
		spiders_tab.append(spider)

if os.path.isfile(args.L):
	with open(f"{args.L}","r") as fichier:
		urls = fichier.readlines()
else:
	urls = [args.L]

# retriving content

for url in urls:
	url = url.replace("\n","")
	if url =="":
		continue
	if not "https://" in url and not "http://" in url:
		url = "https://" + url
	printf(f" {url}",green)

	try:
		response = requests.get(url, headers=headers, timeout=3)
		curl_result = response.content.decode('utf-8')
	except:
		print("\t" +red+ "connection error!")
		continue

# checking Core version

	core_version = ""
	match = re.search(r'<meta name="generator" content="WordPress ([\d]+\.[\d\.]+)', curl_result)

	if match:
		core_version = match.group(1)

	if core_version =="" or "Download" in core_version or ".com" in core_version:
		print(f"WordpressCore version: "+yellow+"not detected"+white)
	else:	
		print(f"WordpressCore version: "+yellow+core_version+white)

# detection core vuln via API
		if not core_version in all_core_version_tab:
			url = f"https://www.wpvulnerability.net/core/{core_version}"
			try:
				response = requests.get(url)
				with open(f"vulnDatabase/coreVuln/{core_version}", 'wb') as f:
					f.write(response.content)
			except:
				printf(" API error", red)
				continue

		if core_version !="":
			core_vulns = check_core_vulns(core_version)
			if len(core_vulns) != 0:
				show_vulns(core_vulns)
				#
				#
				# Need help here for auto-exploit module
				#
				#

			
		#exit()
		"""
		os.system(f"searchsploit Wordpress Core {coreVersion} | grep -i WordPress > /tmp/coreVuln.txt")
		with open("/tmp/coreVuln.txt","r") as f:
			coreVulns = f.readlines()
		for coreVuln in coreVulns:
			coreVuln = coreVuln.replace("\n","")
			coreVuln = coreVuln.replace("  ","")
			print("\t\t"+yellow+coreVuln+white)
		"""
#
# passive theme detection
#

	print(blue+"themes:"+white)

	pattern_themes_without_version = r"/themes/([^/\"\';]+)/"
	pattern_themes_with_version = r'\/themes\/([^/\"\';]+).*[?"\']ver=([\d]+\.[\d\.]+)'

	themes_with_version = re.findall(pattern_themes_with_version,curl_result)
	themes_without_version = list(set(re.findall(pattern_themes_without_version,curl_result)))
	themes = themes_without_version + themes_with_version


	#with open('/tmp/themes.txt', 'w') as file:
	#	for theme in themes:
	#		file.write(theme + '\n')

# searching theme version(s)
	theme_dict={}
	theme_tab=[]
	for theme_without_version in themes_without_version:
		if theme_without_version == "\n":
			continue

# the best occurence wins
		cmt={}
		for theme_with_version in themes_with_version:
			if type(theme_with_version) is tuple:
				theme = theme_with_version[0]
				version = theme_with_version[1]

				if theme_without_version in theme and version != core_version and version !="":
					if version in cmt:
						cmt[version] += 1 
					else:
						cmt[version] = 1

		if cmt !={}:
			theme_version = max(cmt, key=cmt.get)
		else:
			theme_version=""

		theme_dict[theme_without_version] = theme_version

# grabbing readme.txt
		try:
			response = requests.get(f'{url}/wp-content/themes/{theme_without_version}/style.css', headers=headers, timeout=3)
		except:
			printf(" connection error", red)
			continue

		version_regex = r'Stable tag: ([\d]+\.[\d\.]+)'
		match = re.search(version_regex, response.text)

		if match:
			version = match.group(1)
			theme_dict[theme_without_version] = version

	theme_tab.append(theme_dict)	

# displaying
	for theme_dict in theme_tab:
		for key in theme_dict.keys():
			print("      "+ key, theme_dict[key])

# calling API for vulns
			theme = key.rstrip("\n")
			if theme =='':
				continue

			theme_version=theme_dict[key]

			if not theme in all_themes_tab:
				try:
					response = requests.get(f'https://www.wpvulnerability.net/theme/{theme}', timeout=3)
					with open(f'vulnDatabase/themesVuln/{theme}', 'wb') as file:
						file.write(response.content)
				except:
					printf(" API error", red)
					continue

				all_themes_tab.append(theme)

			if theme_version !="":
				theme_vulns = check_theme_vulns(theme, theme_version)
				if len(theme_vulns) != 0:  
					show_vulns(theme_vulns,2)
					#
					#
					# Need help here for auto-exploit module
					#
					#



			"""
			os.system(f"searchsploit Wordpress theme {theme} {theme_version} | grep -i WordPress > /tmp/themeVuln.txt")
			with open("/tmp/themeVuln.txt","r") as f:
				themeVulns = f.readlines()
			for themeVuln in themeVulns:
				themeVuln = themeVuln.replace("\n","")
				themeVuln = themeVuln.replace("  ","")
				print("\t\t\t\t"+yellow+themeVuln+white)
			"""


#
# passive and active plugins detection
#	

	print(blue+"plugins:"+white)

	pattern_plugins_without_version = r"/plugins/([^/\"\';]+)/"
	pattern_plugins_with_version = r'\/plugins\/([^/\"\';]+).*[?"\']ver=([\d]+\.[\d\.]+)'

	plugins_with_version = re.findall(pattern_plugins_with_version,curl_result)
	plugins_without_version = list(set(re.findall(pattern_plugins_without_version, curl_result)))
	plugins_tab = plugins_without_version + plugins_with_version

# launching spiders:
	spiders_process_tab = []
	spiders_results_tab = []
	spider_name = []
	spider_url = []
	spider_regex = []
	spider_headers = [] 
	#print(spiders_tab)

# building arguments
	for spider in spiders_tab:
		spider_name.append(spider[0].rstrip("\n"))
		spider_url.append(url + spider[1].rstrip("\n"))		
		spider_regex.append(spider[2].rstrip('\n'))
		spider_headers.append(headers)

# multi-thread
	with ThreadPoolExecutor() as executor:
		with requests.session() as session:

			for result in executor.map(get_spider, spider_name, spider_url, spider_regex, spider_headers, [session]*len(spiders_tab)):
				if result is not None:
					spiders_results_tab.append(result)
			executor.shutdown(wait=True)

#
# launching templates
#
	templates_results_tab = []
	for template in templates_tab :
		template_regex =  template[0].rstrip("\n")
		template_nb_group = template[1].rstrip("\n")
		if len(template) >2:
			template_name = template[2].rstrip("\n")
		else:
			template_name = None
		
		p = extract_plugins_with_template(curl_result, template_regex, template_nb_group , template_name)
		templates_results_tab.extend(p)
	
# concat plugins:
	plugins = plugins_tab + templates_results_tab + spiders_results_tab
	list_plugins = []
	for plugin in plugins:
		if type(plugin) is tuple:
			list_plugins.append(plugin[0])
		else:
			list_plugins.append(plugin)

	
# unique plugins
	list_plugins = sorted(list(set(list_plugins)))

# retrieving readme.txt
	readme_results_dict = {}
	readme_url_tab = []
	readme_regex_tab = []

	readme_results_dict = {}

	for plugin in list_plugins:
		readme_url_tab.append( url + '/wp-content/plugins/' +plugin + '/readme.txt' )
		readme_regex_tab.append( r'Stable tag:\s*(\d+\.\d+(\.\d+)?)' )

	with ThreadPoolExecutor() as executor:
		with requests.session() as session:			
			for result in executor.map(get_spider, list_plugins, readme_url_tab, readme_regex_tab, [headers]*len(list_plugins), [session]*len(list_plugins)):
				if result is not None:
					readme_results_dict[result[0]] = result[1]
			executor.shutdown(wait=True)

# searching plugin version
	plugin_dict = {}
	plugin_tab=[]
	for plugin_in_list in list_plugins:

		cmt={}
# best occurence wins
		for plugin_raw in plugins:
			if type(plugin_raw) is tuple:
				plugin = plugin_raw[0]
				version = plugin_raw[1]

				if plugin_in_list in plugin and version != core_version and version !="":
					if version in cmt:
						cmt[version] += 1 
					else:
						cmt[version] = 1
		#print(plugin_in_list, cmt)
		if cmt !={}:
			plugin_version = max(cmt, key=cmt.get)
			#print(plugin_version)
		else:
			plugin_version=""

		plugin_dict[plugin_in_list] = plugin_version

# get readme.txt
		if plugin_in_list in readme_results_dict.keys():
			c = readme_results_dict[plugin_in_list]
			if c !="trunk" and c !="" and "." in c and c is not None:
				plugin_dict[plugin_in_list] = c

	plugin_tab.append(plugin_dict)	

# displaying
	for plugin_dict in plugin_tab:
		for key in plugin_dict.keys():
			print("\t", key, plugin_dict[key])

# calling API for vulns
# detection vuln via API

			plugin_version=plugin_dict[key]
			#print(plugin)
			plugin = key
			if plugin =='':
				continue

			#exit()
			if not plugin in all_plugins_tab:
				try:
					response = requests.get(f'https://www.wpvulnerability.net/plugin/{plugin}', timeout=3)
					with open(f'vulnDatabase/pluginsVuln/{plugin}', 'wb') as file:
						file.write(response.content)
				except:
					printf(" API error", red)
					continue

				all_plugins_tab.append(plugin)
			if plugin_version != "":
				pluginVulns = check_plugin_vulns(plugin, plugin_version)
				if len(pluginVulns) != 0:  
					show_vulns(pluginVulns,2)
					#
					#
					# Need help here for auto-exploit module
					#
					#

	# searching authors:
	author_set = {}
	author_set_sorted_keys = []
	XML_list = []

	try:
		response = requests.get(url+"/wp-json/wp/v2/users/", headers=headers, timeout=3)
		author_set = get_users_API(response.text)
		
	except:
		pass
	try:
		response = requests.get(url+"/feed", headers=headers, timeout=3)
		XML_list = get_users_feed(response.text)

	except:
		pass
	
	author_set_sorted_keys = sorted(author_set)
	if author_set_sorted_keys != [] or XML_list != []:
		print(Fore.BLUE+"authors:"+Fore.WHITE)

	if author_set_sorted_keys != []:
		for keys in author_set_sorted_keys:
			print(f"{keys}: {author_set[keys]} ")

	if XML_list != []:
		items_in_dico = [author_set[key] for key in author_set ]
		for user in XML_list :
			if not user in items_in_dico:
				print(user)

	print()

print(reset)
exit()
