
Backup Slave Server
===================

Or also BS server :D

What?
-----

A simple server (not HTTP but TLS) that accepts backup files to be dropped on
disk for storage.

But... why?
-----------

Well I was using FTPS but it was a bit involved. SSL issues truncating my files
or problems such as people bruteforcing the FTP server made me take this
decision. FTP has also a much bigger attack surface than this service,
requiring more ports, complex protocol, etc.

How
---

The server is a simple C++ server, that uses OpenSSL library, and listens on a
port waiting for a file to be pushed. The backups are generally indexed on a
tuple: (object name, version/date, backup data, max copies). The server will
drop the file on disk, and delete older backups according to metadata so that
only N backups are kept.

Practical stuff
---------------

In oder to setup a server just build it, a simple "make" is enough.
Dependencies are OpenSSL and libconfig, and build time dependencies are C++17
friendly compiler and of course the OpenSSL and libconfig headers.

Once that is done, run it like:

```
./bsserver /etc/myconfig
```

The config file can look like:

```
password = "s3cur3p4ss";
port = 12345;
dir = "/my/backup/dir";
keyfile = "key.pem";
certfile = "cert.pem";
max-connections = 50;
user = "nobody";

backup-targets = (
  {
    name = "pictures_backup";
    max-copies = 3;
    rate-limit = {
      period = 24;  // Max 1 backup every 24h
      copies = 1;
    };
  },
  {
    name = "docs_backup";
    max-copies = 10;
    rate-limit = {
      period = 720;  // Max 5 backups per month
      copies = 5;
    };
  }
);
```

If `user` is specified, the server expectes to be run as root, and will
drop its privileges to that user. It will still be able to read any root
owned cert/key files.

The server requires an SSL certificate, however if that's too complicated
for your setup, just generate a self-signed cert and key. That means that
clients will need to ignore SSL errors (see below).

To push files to be backed-up run the CLI command and specify the server
address, backup name, password and obviously the file to copy. The `--copies`
argument will make the server delete the old backups if they exceed that
number of copies.

```.
./bscli.py --pass s3cur3p4ss --host 127.0.0.1:12345 --file mybackup.tgz --name docs-backup --copies 10
```

In order to skip SSL certificate validation use `--nocert`. In the future
the CLI could take a certificate as argument so that self-signed certs can
be used ensuring end-to-end trust.


