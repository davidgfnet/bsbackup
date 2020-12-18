#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys, os, ssl, socket, argparse, hashlib, struct, tqdm

def npad(bchar, padding=256):
	return bchar + b"\x00" * (padding - len(bchar))

def fhash(fname):
	h = hashlib.sha256()
	fsize = 0
	with open(fname, 'rb') as f:
		while True:
			data = f.read(1024*1024)
			if not data:
				break
			h.update(data)
			fsize += len(data)
	return h.digest(), fsize

def check_host_name(peercert, name):
	"""Simple certificate/host name checker.  Returns True if the
	certificate matches, False otherwise.  Does not support
	wildcards."""
	# Check that the peer has supplied a certificate.
	# None/{} is not acceptable.
	if not peercert:
		return False
	if peercert.has_key("subjectAltName"):
		for typ, val in peercert["subjectAltName"]:
			if typ == "DNS" and val == name:
				return True
	else:
		# Only check the subject DN if there is no subject alternative
		# name.
		cn = None
		for attr, val in peercert["subject"]:
			# Use most-specific (last) commonName attribute.
			if attr == "commonName":
				cn = val
		if cn is not None:
			return cn == name
	return False

parser = argparse.ArgumentParser(prog='bscli')
parser.add_argument('--host', dest='host', required=True, help='Hostname (+port) of the backup backend')
parser.add_argument('--pass', dest='pwd', required=True, help='String password to authenticate with server')
parser.add_argument('--name', dest='name', required=True, help='Name of the backup to issue')
parser.add_argument('--file', dest='pfile', required=True, help='File to backup')
parser.add_argument('--nocert', dest='nocert', action="store_true", help='Ignore SSL cert errors (DISCOURAGED!)')
args = parser.parse_args()

# Calculate the hash in advance since it takes a while
print("Calculating file hash")
filehash, filesize = fhash(args.pfile)

hostname, port = args.host.split(":")

print("Connecting to remote server")
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
if not args.nocert:
	ctx.verify_mode = ssl.CERT_REQUIRED
	ctx.check_hostname = True
	ctx.load_default_certs()
sock = ctx.wrap_socket(sock, server_hostname=hostname)
sock.connect((hostname, int(port)))

# Authenticate
challenge = sock.read(32)
assert len(challenge) == 32
response = hashlib.sha256(challenge + hashlib.sha256(args.pwd.encode('utf-8')).digest() + bytearray(list(range(64)))).digest()
sock.write(response)
print("Connection established, authentication started")

# Proceed to send the backup request
sock.write(npad(args.name.encode("utf-8")))
sock.write(filehash)
sock.write(struct.pack("!Q", filesize))

# Now push the file!
with open(args.pfile, 'rb') as f:
	pbar = tqdm.tqdm(unit="B", unit_scale=True, total=os.path.getsize(args.pfile), disable=None)
	while True:
		data = f.read(1024*1024)
		if not data:
			break
		pbar.update(len(data))
		sock.write(data)

# Read back some error/info message maybe?
size = ord(sock.read(1))
code = sock.read(1)
mesg = sock.read(size).decode("utf-8")
sock.close()

if code == b"E":
	print("ERROR Message from server:", mesg)
	sys.exit(1)
elif code == b"O":
	print("SUCCESS! Message from server:", mesg)
	sys.exit(0)
else:
	print("Unknown response from server! Panic!")
	sys.exit(1)
