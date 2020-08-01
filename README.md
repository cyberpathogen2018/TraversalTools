
# pylfi
Simple tool to assist with directory traversal, local file inclusion brute forcing.

Some payloads can be found as part of Burp Suite: https://github.com/tennc/fuzzdb/tree/master/dict/BURP-PayLoad/LFI

TODO: enable RFI with a simple-webserver and reverse shell that can be injected.
TODO: 



```
usage: pylfi.py [-h] [-u URL] [-p PATH_TRAVERSAL_STRING] [-w WORDLIST] [-v] [-o OUTDIR] [-t] [-r REMOTE]

Automates directory traversal and LFI checks.

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     Base URL to directory traversal vulnerability. e.g http://hostname/path?arg=
  -p PATH_TRAVERSAL_STRING, --path_traversal_string PATH_TRAVERSAL_STRING
                        The string required to reach the root directory. e.g. ../../../..
  -w WORDLIST, --wordlist WORDLIST
                        Specify an LFI wordlist. Wordlists are expected to be absolute paths on target system
  -v, --verbose         increase output verbosity
  -o OUTDIR, --outdir OUTDIR
                        Specify a directory relative to the current directory to save files. Filenames will be flattened in here
  -t, --traversal       Prints some example directory traversal strings to try.
  -r REMOTE, --remote REMOTE
                        TODO: Not Implimented. Starts a simple webserver and attempts a remote file inclusion

As an alternative to the commandline, params can be placed in a file, one per line, and specified on the commandline like 'divinc.py @params.conf'.
```

