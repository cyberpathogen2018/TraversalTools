
# pylfi
Simple tool to assist with directory traversal, local file inclusion brute forcing.

Some payloads can be found as part of Burp Suite: https://github.com/tennc/fuzzdb/tree/master/dict/BURP-PayLoad/LFI

TODO: 
- Enable RFI with a simple-webserver and reverse shell that can be injected.
- Enumerate /proc for useful information  (e.g. look at /proc/net/tcp, /proc/net/stat and then brute force through /proc/<PID>/tcp to find more info on a listening port


