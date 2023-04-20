from multiprocessing import Pool, cpu_count
from os import getpid, getppid
import sys
import time
import socket
import ssl
import re

def get_handler(pid, host, port, list_data):
    #print('GET SubProcess %d ' % pid)
    host = host
    bufsize = 4096
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if port == 443:
        sock = ssl.wrap_socket(sock, ca_certs=None, cert_reqs=ssl.CERT_NONE, ssl_version = ssl.PROTOCOL_TLS)
    sock.connect((host, port))

    cnt = 0
    for i, req in enumerate(list_data):
        data_to_send = bytes.fromhex(req)
        sock.send(data_to_send)
        res = sock.recv(bufsize).decode('utf-8')
        if not 'close' in res:
            cnt = i
        else:
            print('GET SubProcess %d, killing' % pid)
            print(bytes.fromhex(list_data[i-1]))
            print(bytes.fromhex(list_data[i]))
            print(res)
            sys.exit()

    print('GET SubProcess %d has sent %d requests' % (pid, cnt))
    sock.close()
    return

def post_handler(pid, host, port, list_data):
    #print('POST SubProcess %d ' % pid)
    host = host
    bufsize = 4096
    cnt = 0
    for i, req in enumerate(list_data):
        #print('POST SubProcess %d connecting...' % pid)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if port == 443:
            sock = ssl.wrap_socket(sock, ca_certs=None, cert_reqs=ssl.CERT_NONE, ssl_version = ssl.PROTOCOL_TLS)
        sock.connect((host, port))
        
        try:
            data_to_send = bytes.fromhex(req)
        except Exception as e:
            data_to_send = bytes.fromhex(req.replace('nkedentitybody', ''))

        sock.send(data_to_send)
        res = sock.recv(bufsize).decode('utf-8')
        cnt = i
        sock.close()
    print('POST SubProcess %d has sent %d requests' % (pid, cnt))
    return


'''
The hex data can contain F5 ether trailer that follows 0d0a0d0a if it is GET/HEAD.
Sending the data as is on Keep-Alive session confuses the DUT BigIP, so this fucntion removes ether trailer for GET/HEAD.

This can be more complicated with POST/PUT/PATCH etc.
These can be Content-Length or chunk, so difficult to determine where the end of actual data is.

An imperfect but easy/practical solution is that to open a new connection for each POST, and let the receiver parse the data and 
let the receiver ignoring the data after the end. Negative side of this solution is too many connections/over-head if your data
has a large number of POST/PUT/PATCH requests.

'''
def split_get_post(data):
    get_data = []
    post_data = []
    for i,r in enumerate(data):
        # Remove f5 ether trailer for GET
        if r[:6] == '474554' or r[:8] == '48454144':
            if len(re.findall('0d0a0d0a', r)) > 1:
                print('GET has more than 2 \r\n\r\n')
                sys.exit()
            m = re.search('0d0a0d0a', r)
            try:
                get_data.append(r[:m.end()])
            except Exception as e:
                #print(r)
                #sys.exit()
                continue

        # POST, PUT, PATCH
        elif r[:10] == '504f535420' or r[:8]  == '50555420' or r[:12] == '504154434820':
            ''' 
            The imperfect/easy/practical sol, just append 'r' in the list.
            And comment out everything after that
            '''
            post_data.append(r)
           
            '''
             Complex sol that tries to parse 
            ''' 

            """
            is_chunked = False
            len_body = 0
            # Determine header part
            end_of_header = r.find('0d0a0d0a') + 7
            # Check if 'Content-Length' exists
            cl = r.find('436f6e74656e742d4c656e677468') # Content-Length
            if cl == -1:
                cl = r.find('636f6e74656e742d74797065') # content-length
            if cl == -1 or cl > end_of_header:
                cl = None
            # Check if 'Content-Encoding' exists 
            ce = r.find('636f6e74656e742d656e636f64696e67') # Content-Encoding
            if ce == -1:
                ce = r.find('436f6e74656e742d456e636f64696e67') # content-encoding
            if ce == -1 or ce > end_of_header:
                ce = None

            if cl and ce:
                print('both CL and CE exists, error')
                print(r)
                sys.exist()
            elif not cl and not ce:
                print('neither CL nor CE exists, error')
                print(r)
                sys.exist()
            # POST is with Content-Length
            elif cl and not ce:
                end_of_cl_hdr = cl+ 27
                cl_val = r[end_of_cl_hdr : (end_of_cl_hdr + r[end_of_cl_hdr: ].find('0d0a0d0a'))].replace('3a', '').replace('20', '')
                try:
                    cl_val_ascii = bytes.fromhex(cl_val).decode('utf-8')
                except Exception as e:
                    print(e)
                    print('request hex: %s' % r)
                    print('cl: %d' % cl)
                    print(r[:cl])
                    print('end_of_cl_hdr: %d' % end_of_cl_hdr)
                    print(r[:end_of_cl_hdr])
                    print('cl_val: %s' % cl_val)
                    sys.exit()
                try:
                    len_body = int(cl_val_ascii)
                except Exception as e:
                    print(e)
                    print('Content-Length INT convert failure')
                    print('cl_val: %s' % cl_val)
                    print('cl_val_ascii: %s' % cl_val_ascii)
                    sys.exit()
                post_data.append(r[ : end_of_header + len_body])
            # POST is with Content-Encoding
            elif ce and not cl:
                end_of_ce_hdr = ce + 31
                ce_val = r[end_of_ce_hdr : (end_of_ce_hdr + r[end_of_ce_hdr].find('0d0a0d0a'))].replace('3a', '').replace('20', '')
                ce_val_ascii = bytes.fromhex(ce_val).decode('utf-8')
                if 'chunked' in ce_val_ascii.lower():
                    is_chunked = True
                if is_chunked == False:
                    print('TE header found but value is not chunked: %s' % ce_val_ascii)
                    sys.exit()
                end_of_chunks = r[end_of_header:].find('0d0a300d0a0d0a') + 13
                if end_of_chunks == -1:
                    print('Chunk end is not found')
                    print(r[end_of_header:])
                    sys.exit()
                post_data.append(r[ : end_of_header + end_of_chunks])
            """
    return get_data, post_data


def sig_handler(signum, frame):
        sys.exit(0)

if __name__ == '__main__':

    args = sys.argv
    if len(args) != 6:
        print('Syntax Error: python3 sock.py HOST PORT FILE N_OF_CONN')
        sys.exit()
    host = args[1]
    port = int(args[2])
    hex_file = args[3]
    n_of_conn = int(args[4])
    method = args[5]
    if not method == 'both' and not method == 'get' and not method == 'post':
        print('set method [both|get|post]')
        sys.exit()

    print("PID: %d, Available CPU cout is: %d" % (getpid(), cpu_count()))

    with open(hex_file) as f:
        d = f.readlines()
    print('Number of requests in the file is %d' % len(d))

    get_data, post_data = split_get_post(d)

    print('Number of GET/HEAD in the file is %d' % len(get_data))
    print('Number of POST/PUT/PATCH in the file is %d' % len(post_data))
    print('Number of connection is %d' % n_of_conn)

    p = Pool(n_of_conn)
    procs = []
    if method == 'both':
        r_in_get_conn = int(len(get_data) / int((n_of_conn/2)) )
        r_in_post_conn = int(len(post_data) / int((n_of_conn/2)) )
        print('Number of requests in a connection(SubProcess) is GET: %d, POST: %d' % (r_in_get_conn, r_in_post_conn))
        for i in range(int(n_of_conn/2)):
            if i == (int(n_of_conn/2)-1): # last slice
                p.apply_async(get_handler, args=[i, host, port, get_data[i*r_in_get_conn : ]])
                procs.append(p)
            else:
                p.apply_async(get_handler, args=[i, host, port, get_data[i*r_in_get_conn : (i+1)*r_in_get_conn]])
        for i in range(int(n_of_conn/2)):
            if i == (int(n_of_conn/2)-1): # last slice
                p.apply_async(post_handler, args=[i, host, port, post_data[i*r_in_post_conn : ]])
            else:
                p.apply_async(post_handler, args=[i, host, port, post_data[i*r_in_post_conn : (i+1)*r_in_post_conn]])
    elif method == 'get':
        r_in_get_conn = int(len(get_data) / int((n_of_conn)) )
        print('Number of requests in a connection(SubProcess) is GET: %d' % (r_in_get_conn))
        for i in range(int(n_of_conn)):
            if i == (int(n_of_conn)-1): # last slice
                p.apply_async(get_handler, args=[i, host, port, get_data[i*r_in_get_conn : ]])
                procs.append(p)
            else:
                p.apply_async(get_handler, args=[i, host, port, get_data[i*r_in_get_conn : (i+1)*r_in_get_conn]])
    elif method == 'post':
        r_in_post_conn = int(len(post_data) / int((n_of_conn)) )
        print('Number of requests in a connection(SubProcess) is POST: %d' % (r_in_post_conn))
        for i in range(int(n_of_conn)):
            if i == (int(n_of_conn)-1): # last slice
                p.apply_async(post_handler, args=[i, host, port, post_data[i*r_in_post_conn : ]])
            else:
                p.apply_async(post_handler, args=[i, host, port, post_data[i*r_in_post_conn : (i+1)*r_in_post_conn]])

    print('Waiting for all subprocesses done...')
    p.close()
    p.join()
    print('All subprocesses done.')
