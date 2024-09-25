# Website analyzer. 
 Automatic tool for analyzing a set of website. The tool takes as input a .txt file with websites. The tool assesses these parameters on a given set of websites:
 - If HTTPS exist. If a website, for any reason, do not enforce HTTPS, it will be excluded from further testing.
 - If redirection from HTTP to HTTPS exists
 - If the websites support or do not support TLS1, TLS1.1, TLS1.2, and TLS1.3.
 - If some HTTPS security headers are implemented. If so, checks the basic correctness of them.
 - If the websites expose revealing information in the headers, for example "Server".
 - If the websites pick a secure cipher suite from the client. They are ranked: insecure, weak, secure, recommended.
 - If the websites will pick a cipher suite containing SHA-1 (deprecated hash functin) or CBC (Lucky13 vulnerability)
 - If the websites implement a "security.txt". If so, checks the basic correctness of the implementation.
## Acceptable usage
Not to be used for malicious purposes.
## Known bugs/problems
- Sometimes in the exported graphs, it does not show percentages on the bars.
- Maximum number of websites is 100.
## Instructions
### Preliminaries
Use Python 3.9.13.
Install the dependencies:
```
pip3 install -r requirements.txt
```
The given .txt file with websites **MUST** only contain one website per line. It should not include subdomains, *http://* or *https://*, or *www*.

Example .txt file to give the tool:
```
example.com
google.com
linkedin.com
```
### Using the tool
The tool is used using the command with Python 3.9.13 installed:
```
python tool.py websites.txt
```
