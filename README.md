# Directory Traversal Tools

## pylfi
Simple tool to assist with directory traversal, and eventually local file inclusion brute forcing. 

(Yes I know it doesn't do LFI... yet. It will. I really liked the name though.)

Run it with the target URL, the traversal string, 

This only works on simple directory traversal in the URL, e.g. http://example.com/index.php?page=../../../etc/passwd

One unique feature that I haven't seen elsewhere is the ability to write to disk anything downloaded, in a flattened filename format.

Some payloads can be found as part of Burp Suite: https://github.com/tennc/fuzzdb/tree/master/dict/BURP-PayLoad/LFI

TODO: 
- Enable RFI with a simple-webserver and reverse shell that can be injected.
- Enumerate /proc for useful information  (e.g. look at /proc/net/tcp, /proc/net/stat and then brute force through /proc/<PID>/tcp to find more info on a listening port


## proc_bruteforce.py
Tool to iterate through /proc/<PID> to find useful information. 
  
  
