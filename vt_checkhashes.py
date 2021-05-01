#!/usr/bin/python3

__author__  = 'L0rdSt0N3d'
__version__ = '3.8.5'

"""
Check file hashes with VirusTotal API. 
In order to execute this script succesfully you need to install the 'virustotal3' module.
--> https://github.com/tr4cefl0w/virustotal3
To know how to use it try -h or --help.
"""
import sys, getopt, csv
from time import sleep



# Try to import module virustotal3.core. Exits if error.
try:
	import virustotal3.core as vt3core
except ModuleNotFoundError:
	print("Module virustotal3 is missing. Check https://github.com/tr4cefl0w/virustotal3")
	sys.exit(1)

def main(argv):

	try:
		opts, args = getopt.getopt(argv,
		"hk:K:f:H:o:",
		["apiKey=","apiKeyFile=","hashesFile=", "help","output="])
	except getopt.GetoptError:
		print("Something went wron... Try -h or --help")
		sys.exit(2)
	
	#PARAMETERS
	csv_file="results.csv"
	hash_file=""
	api_key=""
	
	# Get parameters
	for opt, arg in opts:
		if opt in ['-h', '--help']:
			print_help()
			sys.exit()
			
		elif opt in ["-k", "--apiKey"]:
			api_key = arg
			
		elif opt in ["-K", "--apiKeyFile"]:
			with open(arg) as api_file:
				api_key = api_file.read().rstrip('\n')
				
		elif opt in ["-H", "--hashesFile"]:
			hash_file = arg
			try:
				num_files = sum(1 for line in open(hash_file, "r"))
			except:
				print("Cannot open file: ", hash_file)
				sys.exit(3)
		elif opt in ["-o", "--output"]:
			csv_file = arg
	
	if not hash_file:
		print("Missing parameter: hashesFile")
		sys.exit(4)
	elif not api_key:
		print("Missing parameter: APIKEY")
		sys.exit(4)
	else:
		results = send_requests(hash_file, api_key,num_files)
		save_to_csv(results, csv_file)

		
def send_requests(hash_file, api_key, num_files):
	results = dict()
	# File handler class 4 VT
	vt_files = vt3core.Files(api_key)
	
	with open(hash_file, "rt") as file:
		i = 1
		for line in file:
			entry = line.split("  ") # MD5SUM returns syntax is <hash><two spaces><filename>
		
			# Get Data (Dictionary) from file's hash
			print("\rSubmiting File:                      ", "\n-- Name: ", entry[1].rstrip('\n'), "\n-- Hash: ", entry[0])
			print("#Progress: (%d/%d)" % (i, num_files), end='\r')
			sys.stdout.flush()
			file_data = vt_files.info_file(entry[0])
			
			# Get Last Analysis Stats / keys = [harmless, type-unsupported, suspicious, confirmed-timeout, 
			# timeout, failure, malicious, undetected]
			stats = file_data['data']['attributes']['last_analysis_stats']
			print("----> Harmless: ", stats["harmless"], "             ")
			print("----> Suspicious: ", stats["suspicious"])
			print("----> Malicious: ", stats["malicious"])
			print("----> Undetected: ", stats["undetected"])
			print("\n# Progress: (%d/%d)" % (i, num_files), end='')
			sys.stdout.flush()
			i+=1
			results[entry[1]]=[entry[0],stats]
			
			if(i != num_files + 1):
				sleep(15)
			
	file.close()
	return results
	
def save_to_csv(results, csv_file):
	print("\nSaving results to '" + csv_file + "'...")
	with open(csv_file, 'w', newline='') as csv_file:
		fields = ['Filename','MD5','Harmless','Suspicious','Malicious','Undetected']
		wr = csv.DictWriter(csv_file, fieldnames=fields)
		wr.writeheader()
		for key, value in results.items():
			wr.writerow({'Filename' : key,
						'MD5' : value[0],
						'Harmless' : value[1]["harmless"],
						'Suspicious' : value[1]["suspicious"],
						'Malicious' : value[1]["malicious"],
						'Undetected' : value[1]["undetected"]})
		csv_file.close()
						
def print_help():
	print("Analyzes file hashes against VirusTotal API")
	print("\nUsage: " + sys.argv[0] + " [options]")
	print("\nOptions:\n")
	print("\t-h | --help)\n\t\t What you are looking right now.")
	print("	\n\t-H | --hashFile) \n\t\t File containing hashes and file name. (Check md5sum /sha256sum... outputs) \
			\n\t\t Every line in the file must be <hash><space><space><filename>")
	print("\n\t-k | --apiKey)\n\t\t VirusTotal API key. ")
	print("\n\t-K | --apiKeyFile)\n\t\t Reads VirusTotal API key form a file.")
	print("\n\t-o | --output)\n\t\t File to write results. File will be written in csv format. (By default: ./results.csv)")
	print("\n--> In order to work you need to enter at least the APIKEY and the HASHFILE")
	print("\nExample: " + sys.argv[0] + " -K VT_API_KEY.txt -H hashes.txt -o results.csv")
	

if __name__ == '__main__':
	main(sys.argv[1:])
	
	
