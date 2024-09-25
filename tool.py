from OpenSSL import SSL
import ssl
import json
import socket
import requests
import matplotlib.pyplot as plot
import re
import sys

MAX_TIMEOUT = 10
VERIFY_CERTIFICATE = False # This is for testing on localhost (i.e. with self-signed certificate). Should be True when doing "real" tests.

# API for ranking cipher suites based on their security
ciphersuites = None
try:
    r = requests.get("https://ciphersuite.info/api/cs", timeout=MAX_TIMEOUT).json()
    ciphersuites = r['ciphersuites']
except:
    print("ERROR: Could not GET from ciphersuite.info API. Program exited.")
    exit()

# Data for information revealing headers
revealingHeaders = None
try:
    r = requests.get("https://owasp.org/www-project-secure-headers/ci/headers_remove.json", timeout=MAX_TIMEOUT).json()
    revealingHeaders = r['headers']
except:
    print("ERROR: Could not GET from OWASP revealing header API. Program exited.")
    exit()

# TODO: Returns status code only. When presenting data, include if the status code was 200. (not good)
def redirection(website):  
    # Checks if the given website has redirection from HTTP to HTTPS
    try:
        r = requests.get("http://{}/".format(website), allow_redirects=False, timeout=MAX_TIMEOUT, verify=VERIFY_CERTIFICATE)
    except:
        return -1
        
    # 3XX status code means redirection
    return str(r.status_code).startswith('3')


def normal(website):  
    # Performing "normal" connection and noting the TLS version and cipher suite selection
    security = "error" # Setting to "error" from beginning
    try:
        ctx = SSL.Context(SSL.TLS_METHOD)
        conn = SSL.Connection(ctx, socket.create_connection((website, 443)))
        conn.set_connect_state()
        conn.set_tlsext_host_name(website.encode('utf-8'))
        conn.do_handshake()
        for key in ciphersuites:
            for key, value in key.items():
                if value["openssl_name"] == conn.get_cipher_name() or key == conn.get_cipher_name():
                    security = value['security']
    except:
        print("ERROR: When trying to determine cipher suite security level for",website,".")
    finally:
        conn.close()
    return security


def checkRevealingHeaders(rs):
    # Checks if the given list of websites has any information revealing headers
    noRevelingHeaders = 0
    for r in rs:  # Looping through each website (request object)
        for key, value in r.headers.items():
            key = key.lower()
            if key in [x.lower() for x in revealingHeaders]:
                noRevelingHeaders += 1
    return noRevelingHeaders

def securitytxt(website):  
    # Checks if the given website has implementated security.txt. If so, check correctness of it.
    try:    
        r = requests.get("https://" + website + "/.well-known/security.txt", timeout=MAX_TIMEOUT, verify=VERIFY_CERTIFICATE)
        if r.status_code == 200:
            return [True, r]
        elif r.status_code != 200:
            r = requests.get("https://" + website + "/security.txt", timeout=MAX_TIMEOUT, verify=VERIFY_CERTIFICATE)
            if r.status_code == 200:
                return [True, r]
            elif r.status_code != 200:
                return [False, None]
        else:
            print("Weird status code in securitytxt() received.")
    except:
        print("ERROR: Could not connect to",website,"for security.txt existing.")


def securitytxtCorrectness(r):
    try:
        if b'Contact' in r.content and b'Expires' in r.content:
            return 'both'
        elif b'Contact' in r.content:
            return 'contact'
        elif b'Expires' in r.content:
            return 'expires'
        else:
            return 'none'
    except:
        print("ERROR: Could not check",r,"for security.txt correctness.")

def TLS1_3(website):  
    # Checks if the given website supports TLS version 1.3
    try:
        print("TESTING",website)
        ctx = SSL.Context(SSL.TLS_METHOD)
        ctx.set_min_proto_version(SSL.TLS1_3_VERSION)
        ctx.set_max_proto_version(SSL.TLS1_3_VERSION)
        conn = SSL.Connection(ctx, socket.create_connection((website, 443)))
        conn.set_connect_state()
        conn.set_tlsext_host_name(website.encode('utf-8'))
        bool = None
        try:
            conn.do_handshake()
            bool = True
            conn.close()
        except:
            conn.close()
            bool = False
        finally:
            conn.close()
        return bool
    except:
        print("ERROR: Could not connect to", website, "during TLSv1.3 check.")
        return -1

    

def TLS1_2(website): 
    # Checks if the given website supports TLS version 1.2
    try:
        print("TESTING",website)
        ctx = SSL.Context(SSL.TLS_METHOD)
        ctx.set_min_proto_version(SSL.TLS1_2_VERSION)
        ctx.set_max_proto_version(SSL.TLS1_2_VERSION)
        conn = SSL.Connection(ctx, socket.create_connection((website, 443)))
        conn.set_connect_state()
        conn.set_tlsext_host_name(website.encode('utf-8'))
        bool = None
        try:
            conn.do_handshake()
            bool = True
            conn.close()
        except:
            conn.close()
            bool = False
        finally:
            conn.close()
        return bool
    except:
        print("ERROR: Could not connect to", website, "during TLSv1.2 check.")
        return -1


def TLS1_1(website):  
    # Checks if the given website supports TLS version 1.1
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1) # Setting the correct TLS version (change to PROTOCOL_TLSv1_1 for 1.1)
        conn = socket.create_connection((website, 443)) # connecting to HTTPS port
        bool = None
        try:
            SSLsock = context.wrap_socket(conn, server_hostname = website) # wrapping into an SSL socket
            SSLsock.do_handshake() # Handshaking with the client
            SSLsock.close() # if code reaches here without throwing errors, then handshake was successful
            bool = True
            conn.close()
        except:
            bool = False
            conn.close()
        finally:
            conn.close()
        return bool
    except:
        print("ERROR: Could not connect to", website, "during TLSv1.1 check.")
        return -1


def TLS1(website):  
    # Checks if the given website supports TLS version 1.0
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1) # Setting the correct TLS version (change to PROTOCOL_TLSv1_1 for 1.1)
        conn = socket.create_connection((website, 443)) # connecting to HTTPS port
        bool = None
        try:
            SSLsock = context.wrap_socket(conn, server_hostname = website) # wrapping into an SSL socket
            SSLsock.do_handshake() # Handshaking with the client
            SSLsock.close() # if code reaches here without throwing errors, then handshake was successful
            bool = True
            conn.close()
        except:
            bool = False
            conn.close()
        finally:
            conn.close()
        return bool
    except:
        print("ERROR: Could not connect to", website, "during TLSv1 check.")
        return -1

def SHA_1(website):  
    try:
        # Checks if the given website will pick a cipher suite containing SHA-1
        ctx = SSL.Context(SSL.TLS_METHOD)
        ctx.set_min_proto_version(SSL.TLS1_2_VERSION)
        ctx.set_max_proto_version(SSL.TLS1_2_VERSION)
        ctx.set_cipher_list(b"SHA1")
        conn = SSL.Connection(ctx, socket.create_connection((website, 443)))
        conn.set_connect_state()
        conn.set_tlsext_host_name(website.encode('utf-8'))
        bool = None
        try:
            conn.do_handshake()
            bool = True
        except:
            bool = False
        finally:
            conn.close()
        return bool
    except:
        print("ERROR: Could not connect to", website, "during SHA1 check.")
        return -1


def CBC(website):  
    # Checks if the given website will pick a cipher suite containing CBC (Lucky13 vulnerability)
    try:
        ctx = SSL.Context(SSL.TLS_METHOD)
        ctx.set_min_proto_version(SSL.TLS1_2_VERSION)
        ctx.set_max_proto_version(SSL.TLS1_2_VERSION)
        ctx.set_cipher_list(b"CBC")
        conn = SSL.Connection(ctx, socket.create_connection((website, 443)))
        conn.set_connect_state()
        conn.set_tlsext_host_name(website.encode('utf-8'))
        bool = None
        try:
            conn.do_handshake()
            bool = True
        except:
            bool = False
        finally:
            conn.close()
            return bool
    except:
        print("ERROR: Could not connect to", website, "during CBC check.")
        return -1


def makePlot(xAxis, xAxisDenote, colors, title, fileName):
    # Creates a graph of the given data and exports it
    plot.clf()
    print(xAxis)
    plot.bar(xAxisDenote, [round(v, 2) for v in xAxis], color=colors)
    for i in range(len(xAxisDenote)): # Printing percentage on each bar
        plot.text(i, xAxis[i], str(xAxis[i]) + "%", ha="center")
    plot.ylabel('%')
    plot.title(title, pad=10)
    plot.ylim(0, 100)
    plot.savefig(fileName)
    pass


def run(givenFile):
    with open(givenFile, 'r') as file:
        websites = file.readlines()
        totalWebsites = len(websites) # Total number of websites that is tested

        if(totalWebsites < 1):
            print("ERROR: No websites in the given file.")
            exit()

        print("Given file is", givenFile,"with", totalWebsites, "number of websites.")

        # Testing if website reachable over HTTPS. If so, store result (header + body) in requests object for further use.
        print("Testing HTTPS support...")
        rs = []
        HTTPSConnectErrors = 0
        for website in websites:
            websiteFixed = website.replace(' ', '').replace('\n', '').replace('\r', '')
            try:
                r = requests.get("https://" + websiteFixed, timeout=MAX_TIMEOUT, verify=VERIFY_CERTIFICATE)
                rs.append(r)
            except:
                print("Error when connecting to " + websiteFixed + " over HTTPS. Will not be included in further results.")
                websites.remove(website) # If the website does not support HTTPS, it is excluded from future tests
                HTTPSConnectErrors += 1
        
        if len(websites) == 0:
            print("No websites to test. Program exited.")
            exit()

        # HTTPS handshake successful
        xAxis = [((totalWebsites - HTTPSConnectErrors) / totalWebsites) * 100, (HTTPSConnectErrors / totalWebsites) * 100]
        xAxisDenote = ['Yes', 'No (no certificate, wrong host name,\ntimeout reached or other error.)']
        makePlot(xAxis, xAxisDenote, ['green', 'red'], "Successful HTTPS connection?", "HTTPS_normal_connection.png")

        totalWebsites = len(websites) # Updating the total number of website (incase one or more did not support HTTPS and was excluded)

        # HTTP security headers
        # Making all headers (keys and values) into lowercase for more reliability
        headersLowerCase = [{k.lower(): v.lower() for k, v in d.items()} for d in [r.headers for r in rs]]

        # Referrer-Policy
        print("Testing Referrer-Policy support...")
        RP = [r.headers.get('referrer-policy') != None for r in rs] # if they implement, true/false
        implemented = len([v for v in RP if v == True])
        notImplemented = len([v for v in RP if v == False])
        RPValues = [val for val in [r.get('referrer-policy') for r in headersLowerCase if r.get('referrer-policy') != None]]
        RPCorrect = [val for val in RPValues if ("same-origin" in val or "strict-origin" in val or "strict-origin-when-cross-origin" in val or "no-referrer" in val) ] # websites that have implemented correctly

        # Graph for Referrer-Policy implementation
        xAxis = []
        xAxisDenote = ['Yes', 'No']
        if len(RP) > 0:
            xAxis = [(implemented / len(RP)) * 100, (notImplemented / len(RP)) * 100]
        else:
            xAxis = [0, 100]
        makePlot(xAxis, xAxisDenote, ['green', 'red'], "Implemented Referrer-Policy header?", "ReferrerPolicy_implementation.png")

        # Graph for Referrer-Policy correctness
        if implemented > 0: # Atleast if one website implemented this the correctness graph should be created
            xAxis = [(len(RPCorrect) / implemented) * 100, ((implemented - len(RPCorrect)) / implemented) * 100]
            makePlot(xAxis, xAxisDenote, ['green', 'red'], "If Referrer-Policy header implemented, is it correctly\nimplemented?", "ReferrerPolicy_correctness.png")

        # X-Content-Type-Options
        print("Testing X-Content-Type-Options support...")
        XCTO = [r.headers.get('x-content-type-options') != None for r in rs] # if they implement, true/false
        implemented = len([v for v in XCTO if v == True])
        notImplemented = len([v for v in XCTO if v == False])
        XCTOValues = [val for val in [r.get('x-content-type-options') for r in headersLowerCase if r.get('x-content-type-options') != None]]
        XCTOCorrect = [val for val in XCTOValues if ('nosniff' in val) ] # websites that have implemented correctly

        # Graph for X-Content-Type-Options implementation
        xAxis = []
        xAxisDenote = ['Yes', 'No']
        if len(XCTO) > 0:
            xAxis = [(implemented / len(XCTO)) * 100, (notImplemented / len(XCTO)) * 100]
        else:
            xAxis = [0, 100]
        makePlot(xAxis, xAxisDenote, ['green', 'red'], "Implemented X-Content-Type-Options header?", "XContentTypeOptions_implementation.png")

        # Graph for X-Content-Type-Options correctness
        if implemented > 0:
            xAxis = [(len(XCTOCorrect) / implemented) * 100, ((implemented - len(XCTOCorrect)) / implemented) * 100]
            xAxisDenote = ['Yes', 'No']
            makePlot(xAxis, xAxisDenote, ['green', 'red'], "If X-Content-Type-Options header implemented, is it correctly\nimplemented?", "XContentTypeOptions_correctness.png")

        # X-Frame-Options
        print("Testing X-Frame-Options support...")
        XFO = [r.headers.get('x-frame-options') != None for r in rs] # if they implement, true/false
        implemented = len([v for v in XFO if v == True])
        notImplemented = len([v for v in XFO if v == False])
        XFOValues = [val for val in [r.get('x-frame-options') for r in headersLowerCase if r.get('x-frame-options') != None]]
        XFOCorrect = [val for val in XFOValues if ('deny' in val or 'sameorigin' in val) ] # websites that have implemented correctly

        # Graph for X-Frame-Options implementation
        xAxis = []
        xAxisDenote = ['Yes', 'No']
        if len(XFO) > 0:
            xAxis = [(implemented / len(XFO)) * 100, (notImplemented / len(XFO)) * 100]
        else:
            xAxis = [0, 100]
        makePlot(xAxis, xAxisDenote, ['green', 'red'], "Implemented X-Frame-Options header?", "XFrameOptions_implementation.png")

        # Graph for X-Frame-Options correctness
        if implemented > 0:
            xAxis = [(len(XFOCorrect) / implemented) * 100, ((implemented - len(XFOCorrect)) / implemented) * 100]
            makePlot(xAxis, xAxisDenote, ['green', 'red'], "If X-Frame-Options header implemented, is it correctly\nimplemented?", "XFrameOptions_correctness.png")

        # Content-Security-Policy
        print("Testing Content-Security-Policy support...")
        CSP = [r.headers.get('content-security-policy') != None for r in rs] # if they implement, true/false
        implemented = len([v for v in CSP if v == True])
        notImplemented = len([v for v in CSP if v == False])
        CSPValues = [val for val in [r.get('content-security-policy') for r in headersLowerCase if r.get('content-security-policy') != None]]
        CSPCorrect = [val for val in CSPValues if ((('default-src' in val or ('script-src' in val and 'object-src' in val)) and ('data:' not in val and 'unsafe-inline' not in val))) ] # websites that have includeSubDomains

        # Graph for Content-Security-Policy implementation
        xAxis = []
        xAxisDenote = ['Yes', 'No']
        if len(CSP) > 0:
            xAxis = [(len([v for v in CSP if v == True]) / len(CSP)) * 100, (len([v for v in CSP if v == False]) / len(CSP)) * 100]
        else:
            xAxis = [0, 100]
        makePlot(xAxis, xAxisDenote, ['green', 'red'], "Implemented Content-Security-Policy header?", "ContentSecurityPolicy_implementation.png")
            
        # Graph for Content-Security-Policy correctness
        if implemented > 0:
            xAxis = [(len(CSPCorrect) / implemented) * 100, ((implemented - len(CSPCorrect)) / implemented) * 100]
            makePlot(xAxis, xAxisDenote, ['green', 'red'], "If Content-Security-Policy header implemented, is it correctly\nimplemented?", "ContentSecurityPolicy_correctness.png")

        # HSTS  
        print("Testing HSTS support...")
        HSTS = [r.headers.get('strict-transport-security') != None for r in rs] # if they implement, true/false
        implemented = len([v for v in HSTS if v == True])
        notImplemented = len([v for v in HSTS if v == False])
        HSTSValues = [val for val in [r.get('strict-transport-security') for r in headersLowerCase if r.get('strict-transport-security') != None]]
        includeSubDomains = [val for val in HSTSValues if('includesubdomains' in val)] # websites that have includeSubDomains
        maxAge = [v for v in [re.findall(r'\d+', v) for v in HSTSValues] if(int(v[0]) >= 31536000)] # websites that have atleast 31536000 max-age

        # Graph for HSTS implementation
        xAxisDenote = ['Yes', 'No']
        xAxis = []
        if len(HSTS) > 0:
            xAxis = [(len([v for v in HSTS if v == True]) / len(HSTS)) * 100, (len([v for v in HSTS if v == False]) / len(HSTS)) * 100]
        else:
            xAxis = [0, 100]
        makePlot(xAxis, xAxisDenote, ['green', 'red'], "Implements Strict-Transport-Security?", "HSTS_implements.png")

        # Graph for HSTS correctness
        if implemented > 0:
            xAxis = [(len(includeSubDomains) / implemented) * 100, (len(maxAge) / implemented) * 100]
            xAxisDenote = ['includeSubDomains', 'max-age is atleast 31536000']
            makePlot(xAxis, xAxisDenote, ['lightblue'], "Strict-Transport-Security correctness", "HSTS_correctness.png")

        # Checking the website for HTTP header revealing information
        print("Testing revealing headers...")
        result = checkRevealingHeaders(rs) # number of websites that have revealing information
        xAxis = [(result / totalWebsites) * 100, ((totalWebsites - result) / totalWebsites) * 100]
        xAxisDenote = ['Yes', 'No']
        makePlot(xAxis, xAxisDenote, ['red', 'green'], "Revealing unecessary information in header?", "RevealingHeaders.png")

        # Checking security.txt implementation
        print("Testing security.txt support...")
        securitytxtRes = [securitytxt(website.replace(' ', '').replace('\n', '').replace('\r', '')) for website in websites]  # Storing result in a list
        yesProcent = (len([sec for sec in securitytxtRes if sec[0] == True]) / len(securitytxtRes)) * 100
        noProcent = (len([sec for sec in securitytxtRes if sec[0] == False]) / len(securitytxtRes)) * 100
        xAxis = [yesProcent, noProcent]
        xAxisDenote = ['Implements', 'Does not implement']
        makePlot(xAxis, xAxisDenote, ['green', 'red'], "security.txt implementations.", "securitytxt_exists.png")

        # Checking the correctness of the security.txt implementation; i.e., if "Contact" and "Expires" fields exist.
        if yesProcent > 0:
            print("Testing security.txt correctness...")
            securitytxtCorrectnessRes = [securitytxtCorrectness(sec[1]) for sec in securitytxtRes if sec[0] == True]
            bothProcent = 0
            contactProcent = 0
            expiresProcent = 0
            noneProcent = 0
            if len(securitytxtCorrectnessRes) > 0:
                bothProcent = (len([f for f in securitytxtCorrectnessRes if f == 'both']) / len(securitytxtCorrectnessRes   )) * 100
                contactProcent = (len([f for f in securitytxtCorrectnessRes if f == 'contact']) / len(securitytxtCorrectnessRes)) * 100
                expiresProcent = (len([f for f in securitytxtCorrectnessRes if f == 'expires']) / len(securitytxtCorrectnessRes)) * 100
                noneProcent = (len([f for f in securitytxtCorrectnessRes if f == 'none']) / len(securitytxtCorrectnessRes)) * 100
            xAxis = [bothProcent, contactProcent, expiresProcent, noneProcent]
            xAxisDenote = ['Both', 'Only "Contact"', 'Only "Expires"', 'None']
            makePlot(xAxis, xAxisDenote, ['lightblue'], "Out of the websites implemented security.txt, do they include the\nmandatory fields 'Contact' and 'Expires'?", "securitytxt_correctness.png")

        # Doing normal handshake and noting cipher suite selection from server
        print("Testing normal HTTPS handshake cipher suite strength...")
        normalRes = [normal(website.replace(' ', '').replace('\n', '').replace('\r', '')) for website in websites]  # Storing result in a list
        successCountNormal = len(normalRes)
        # Dictionary to store number of recommended, securre, weak, and insecure server cipher picks
        counts = {item: normalRes.count(item) for item in set(normalRes)}
        # Calculating percentages
        weakProcent = counts.get('weak', 0) / successCountNormal * 100
        insecureProcent = counts.get('insecure', 0) / successCountNormal * 100
        secureProcent = counts.get('secure', 0) / successCountNormal * 100
        recommendedProcent = counts.get('recommended', 0) / successCountNormal * 100
        errorProcent = counts.get('error', 0) / successCountNormal * 100

        # Plotting and exporting the graph of the results
        xAxis = [recommendedProcent, secureProcent, weakProcent, insecureProcent, errorProcent]
        xAxisDenote = ['Recommended', 'Secure', 'Weak', 'Insecure', 'Could not connect']
        makePlot(xAxis, xAxisDenote, ['green', 'green', 'yellow', 'red', 'gray'], "Normal handshake, security level of server selected cipher suite.", "normal_handshake_cipher_security.png")

        # Checking redirection from HTTP to HTTPS
        print("Testing redirection from HTTP to HTTPS support...")
        reDir = [redirection(website.replace(' ', '').replace(
            '\n', '').replace('\r', '')) for website in websites]  # Storing results in a list
        reDirImplements = [implements for implements in reDir if implements == True]  # Storing all websites that have redirection in a list
        reDirNotImplements = [implements for implements in reDir if implements == False]  # Storing all websites that does not have redirection in a list
        reDirError = [implements for implements in reDir if implements == -1]  # Returned error
        # Calculating percentages
        yesProcent = (len(reDirImplements) / len(reDir)) *  100
        noProcent = (len(reDirNotImplements) / len(reDir)) * 100
        errorProcent = (len(reDirError) / len(reDir)) * 100
        xAxis = [yesProcent, noProcent, errorProcent]
        xAxisDenote = ['Yes', 'No', 'Could not connect']
        makePlot(xAxis, xAxisDenote, ['green', 'red', 'lightblue'], "Do the given websites redirect from HTTP to HTTPS?", "redirection.png")

        print("Testing SHA1 support...")
        sha1 = [SHA_1(website.replace(' ', '').replace('\n', '').replace('\r', '')) for website in websites]
        SHA1_support = [implements for implements in sha1 if implements == True]
        SHA1_notSupport = [implements for implements in sha1 if implements == False]
        SHA1_error = [implements for implements in sha1 if implements == -1]
        xAxis = [(len(SHA1_support) / len(sha1)) * 100, (len(SHA1_notSupport) / len(sha1)) * 100, (len(SHA1_error) / len(sha1)) * 100]
        xAxisDenote = ["Yes", "No", "Could not connect"]
        makePlot(xAxis, xAxisDenote, ['red', 'green',  'lightblue'], "SHA1 cipher suite support", "SHA1support.png")

        print("Testing CBC support...")
        cbc = [CBC(website.replace(' ', '').replace('\n', '').replace('\r', '')) for website in websites]
        CBC_support = [implements for implements in cbc if implements == True]
        CBC_notSupport = [implements for implements in cbc if implements == False]
        CBC_error = [implements for implements in cbc if implements == -1]
        xAxis = [(len(CBC_support) / len(cbc)) * 100, (len(CBC_notSupport) / len(cbc)) * 100, (len(CBC_error) / len(cbc)) * 100]
        xAxisDenote = ["Yes", "No", "Could not connect"]
        makePlot(xAxis, xAxisDenote, ['red', 'green', 'lightblue'], "CBC cipher suite support", "CBCsupport.png")

        # TLS 1.3
        allTLS1_3 = [TLS1_3(website.replace(' ', '').replace('\n', '').replace('\r', '')) for website in websites]
        TLS1_3support = [implements for implements in allTLS1_3 if implements == True]
        TLS1_3notSupport = [implements for implements in allTLS1_3 if implements == False]
        TLS1_3error = [implements for implements in allTLS1_3 if implements == -1]
        xAxis = [(len(TLS1_3support) / len(allTLS1_3)) * 100, (len(TLS1_3notSupport) / len(allTLS1_3)) * 100, (len(TLS1_3error) / len(allTLS1_3)) * 100]
        xAxisDenote = ["Yes", "No", "Could not connect"]
        makePlot(xAxis, xAxisDenote, ['green', 'red', 'lightblue'], "TLS1_3 versions support", "TLS1_3support.png")

        # TLS 1.2
        allTLS1_2 = [TLS1_2(website.replace(' ', '').replace('\n', '').replace('\r', '')) for website in websites]
        TLS1_2support = [implements for implements in allTLS1_2 if implements == True]
        TLS1_2notSupport = [implements for implements in allTLS1_2 if implements == False]
        TLS1_2error = [implements for implements in allTLS1_2 if implements == -1]
        xAxis = [(len(TLS1_2support) / len(allTLS1_2)) * 100, (len(TLS1_2notSupport) / len(allTLS1_2)) * 100, (len(TLS1_2error) / len(allTLS1_2)) * 100]
        xAxisDenote = ["Yes", "No", "Could not connect"]
        makePlot(xAxis, xAxisDenote, ['green', 'red', 'lightblue'], "TLS1_2 versions support", "TLS1_2support.png")

        # TLS 1.1
        allTLS1_1 = [TLS1_1(website.replace(' ', '').replace('\n', '').replace('\r', '')) for website in websites]
        TLS1_1support = [implements for implements in allTLS1_1 if implements == True]
        TLS1_1notSupport = [implements for implements in allTLS1_1 if implements == False]
        TLS1_1error = [implements for implements in allTLS1_1 if implements == -1]
        xAxis = [(len(TLS1_1support) / len(allTLS1_1)) * 100, (len(TLS1_1notSupport) / len(allTLS1_1)) * 100, (len(TLS1_1error) / len(allTLS1_1)) * 100]
        xAxisDenote = ["Yes", "No", "Could not connect"]
        makePlot(xAxis, xAxisDenote, ['red', 'green', 'lightblue'], "TLS1_1 versions support", "TLS1_1support.png")

        # TLS 1
        allTLS1 = [TLS1(website.replace(' ', '').replace('\n', '').replace('\r', '')) for website in websites]
        TLS1support = [implements for implements in allTLS1 if implements == True]
        TLS1notSupport = [implements for implements in allTLS1 if implements == False]
        TLS1error = [implements for implements in allTLS1 if implements == -1]
        xAxis = [(len(TLS1support) / len(allTLS1)) * 100, (len(TLS1notSupport) / len(allTLS1)) * 100, (len(TLS1error) / len(allTLS1)) * 100]
        xAxisDenote = ["Yes", "No", "Could not connect"]
        makePlot(xAxis, xAxisDenote, ['red', 'green', 'lightblue'], "TLS1 versions support", "TLS1support.png")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("ERROR: Wrong number of arguments. See README for usage.")
        exit()
    run(sys.argv[1])
