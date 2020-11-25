
#define _LARGEFILE64_SOURCE 1
#define _FILE_OFFSET_BITS  64

#include <vector>
#include <thread>
#include <list>
#include <iostream>
#include <chrono>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/signal.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <libconfig.h>
#include "configsrv.h"

#define RET_ERR(x) { std::cerr << x << std::endl; return 1; }


struct t_target {
	// Rotation copy count
	unsigned maxcopies;
	// Rate limiting
	unsigned rl_period, rl_copies;
};

// Make this global to simplify things
std::string backup_dir, master_pass;
std::unordered_map<std::string, t_target> targets;

uint64_t read64n(const uint8_t *b) {
	uint64_t r = 0;
	for (unsigned i = 0; i < 8; i++)
		r = (r << 8ULL) | b[i];
	return r;
}

std::string tohex(const std::string &b) {
	static const char *hexc_ = "0123456789abcdef";
	std::string r;
	for (char c : b) {
		r += hexc_[((uint8_t)c) >> 4];
		r += hexc_[((uint8_t)c) & 15];
	}
	return r;
}

std::string gettodn() {
	char fmtime[128];
	auto tp = std::chrono::system_clock::now();
	const std::time_t t = std::chrono::system_clock::to_time_t(tp);
	std::strftime(fmtime, sizeof(fmtime), "%Y-%m-%d_%H-%M-%S", std::gmtime(&t));
	return fmtime;
}

bool validate(const uint8_t *response, const uint8_t *challenge, const char *pwd) {
	// The validation is as follows:
	// SHA256(challenge + SHA256(pwd) + tail)
	uint8_t pwdhash[32];
	SHA256((uint8_t*)pwd, strlen(pwd), pwdhash);

	uint8_t input[128], checkhash[32];
	memcpy(&input[ 0], challenge, 32);
	memcpy(&input[32], pwdhash,   32);
	for (unsigned i = 64; i < 128; i++)
		input[i] = i-64;
	SHA256(input, sizeof(input), checkhash);

	return !memcmp(checkhash, response, 32);
}

std::vector<std::string> listdir(std::string sdir) {
	std::vector<std::string> ret;
	DIR *d = opendir(sdir.c_str());
	if (d) {
		struct dirent *dir;
		while ((dir = readdir(d)) != NULL)
			if (dir->d_name[0] != '.')
				ret.push_back((sdir + "/") + dir->d_name);
		closedir(d);
	}
	return ret;
}

std::vector<uint64_t> listbackupts(std::string sdir) {
	std::vector<uint64_t> ret;
	for (auto fp : listdir(sdir)) {
		auto p = fp.find_last_of('/');
		std::string fn = p == std::string::npos ? fp : fp.substr(p+1);
		if (fn.size() == 28 && fn[19] == '_') {
			std::tm t;
			std::istringstream ss(fn.substr(0, 19));
			if (ss >> std::get_time(&t, "%Y-%m-%d_%H-%M-%S")) {
				std::time_t time_stamp = timegm(&t);
				ret.push_back(time_stamp);
			}
		}
	}
	return ret;
}

void backup_cleanup(std::string dir, unsigned max_copies) {
	auto files = listdir(dir);
	std::sort(files.begin(), files.end(), std::greater<std::string>());   // Sort from most recent to oldest
	for (unsigned i = max_copies; i < files.size(); i++) {
		std::cout << "Deleting old backup " << files[i] << std::endl;
		unlink(files[i].c_str());
	}
}

class BackupHandler {
public:
	BackupHandler(int clientfd, SSL *ssl, SSL_CTX *ctx)
		: clientfd(clientfd), ssl(ssl), ctx(ctx),
		  th(&BackupHandler::run, this), thread_dead(false) {}
	BackupHandler(const BackupHandler &h) = delete;

	~BackupHandler() {
		SSL_free(ssl);
		SSL_CTX_free(ctx);
	}

	bool eot() const { return thread_dead; }
	void join() { th.join(); }

	void run() {
		// Do backup over the wire
		auto [res, msg] = work();
		std::cout << "Backup complete, success: " << res << ", with message: " << msg << std::endl;

		// Send a response back with error or info.
		return_message(!res, msg);

		// Wait and close connection...
		SSL_shutdown(ssl);
		close(clientfd);

		// Now we are officially dead
		thread_dead = true;
	}

	// Simple read() wrapper
	int sslread(char *buffer, unsigned size) {
		unsigned offset = 0;
		while (offset < size) {
			int r = SSL_read(ssl, &buffer[offset], size - offset);
			if (!r)
				return offset;
			else if (r < 0)
				return r;
			offset += r;
		}
		return offset;
	}

	std::pair<bool, std::string> work() {
		if (SSL_accept(ssl) <= 0)
			return {false, "Failed SSL connection handshake"};

		// Send a random challenge (32 bytes)
		uint8_t cha[32];
		RAND_bytes(cha, sizeof(cha));
		if (sizeof(cha) != SSL_write(ssl, cha, sizeof(cha)))
			return {false, "Could not send initial challenge"};

		// Now wait for the response
		uint8_t resp[32];
		if (sizeof(resp) != sslread((char*)resp, sizeof(resp)))
			return {false, "Could not read request header"};
		std::cout << "Got response" << std::endl;
		if (!validate(resp, cha, master_pass.c_str()))
			return {false, "Authentication failed"};
		std::cout << "Response accepted" << std::endl;

		// Receive the header, with info about the backup
		char bname[256], hash[32];
		uint8_t filesize[8];
		if (sizeof(bname) != sslread(bname, sizeof(bname)))
			return {false, "Failed parsing request header"};
		if (sizeof(hash) != sslread(hash, sizeof(hash)))
			return {false, "Failed parsing request header"};
		if (sizeof(filesize) != sslread((char*)filesize, sizeof(filesize)))
			return {false, "Failed parsing request header"};
		uint64_t fs = read64n(filesize);
		bname[sizeof(bname)-1] = 0;
		std::string backupname(bname), backuphash(hash, sizeof(hash));

		// Sanitize the backupname since it determines the disk location
		std::replace(backupname.begin(), backupname.end(), '/', '_');
		std::cout << "Got backup for " << backupname << " (" << fs << " bytes) with hash " << tohex(backuphash) << std::endl;

		// Check the backup policy and enforce any rate limits
		if (!targets.count(backupname))
			return {false, "Backup is not defined in the server config"};
		const t_target *t = &targets.at(backupname);

		std::string subdirp = backup_dir + "/" + backupname;
		std::string fullpath = subdirp + "/" + gettodn() + "_" + tohex(backuphash).substr(0, 8);
		std::string tmpfullpath = fullpath + ".part";

		if (t->rl_period && t->rl_copies) {
			auto tsl = listbackupts(subdirp);
			// Find the number of backups in the last rl_period hours
			unsigned cnt = 0;
			for (auto ts: tsl)
				if ((signed)ts > time(0) - t->rl_period * 3600)
					cnt++;
			if (cnt >= t->rl_copies)
				return {false, "Too many backups: " + std::to_string(cnt)};
		}

		// Create dir just in case
		mkdir(subdirp.c_str(), 0750);

		// Now proceed to receive bytes from the client.
		SHA256_CTX sctx;
		SHA256_Init(&sctx);
		FILE *fo = fopen(tmpfullpath.c_str(), "wb");
		uint64_t received = 0;
		if (fo) {
			while (received < fs) {
				char tmp[8*1024];
				auto rr = sslread(tmp, std::min((uint64_t)sizeof(tmp), fs - received));
				if (rr <= 0)
					break;
				if (rr != (int)fwrite(tmp, 1, rr, fo))
					break;
				received += rr;
				SHA256_Update(&sctx, tmp, rr);
			}
			fclose(fo);
		}

		// Check hash of the file we just dropped
		uint8_t fhash[32];
		SHA256_Final(&fhash[0], &sctx);

		if (received != fs || memcmp(fhash, hash, 32)) {
			// Cleanup temp files!
			unlink(tmpfullpath.c_str());
			return {false, "Transfer or checksum failed"};
		}

		// Move to its final path
		rename(tmpfullpath.c_str(), fullpath.c_str());

		// Now cleanup the extra files we might have
		backup_cleanup(subdirp, t->maxcopies);

		return {true, "Backup stored successfully"};
	}

private:
	void return_message(bool error, const std::string &msg) {
		char msglen = msg.size();
		SSL_write(ssl, &msglen, 1);
		SSL_write(ssl, error ? "E" : "O", 1);
		SSL_write(ssl, msg.c_str(), msg.size());
	}

	int clientfd;
	SSL *ssl;
	SSL_CTX *ctx;
	std::thread th;
	bool thread_dead;
};

int create_socket(int port) {
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	int s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0) {
		perror("Unable to create socket");
		exit(1);
	}
	if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		perror("Unable to bind port");
		exit(1);
	}
	if (listen(s, 1) < 0) {
		perror("Unable to listen");
		exit(1);
	}
	return s;
}

class SSLFactory {
private:
	std::string keyfile, certfile;
	ConfigServer reader;

public:
	SSLFactory(std::string keyfile, std::string certfile)
		:keyfile(keyfile), certfile(certfile) {}

	SSL_CTX *create() {
		auto *ctx = SSL_CTX_new(TLS_method());
		if (!ctx ||
			!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) ||
			!SSL_CTX_set_max_proto_version(ctx, 0)) {

			perror("Unable to create SSL context");
			ERR_print_errors_fp(stderr);
			return nullptr;
		}

		std::string cert = reader.readfile(certfile);
		BIO *certin = BIO_new_mem_buf(cert.c_str(), cert.size());
		X509 *x = PEM_read_bio_X509_AUX(certin, NULL, NULL, NULL);
		if (!x) {
			ERR_print_errors_fp(stdout);
			return nullptr;
		}
		int ret1 = SSL_CTX_use_certificate(ctx, x);
		SSL_CTX_clear_chain_certs(ctx);
		X509 *ca = NULL;
		while ((ca = PEM_read_bio_X509(certin, NULL, NULL, NULL)) != NULL)
			SSL_CTX_add0_chain_cert(ctx, ca);

		std::string pkey = reader.readfile(keyfile);
		BIO *pkeyin = BIO_new_mem_buf(pkey.c_str(), pkey.size());
		EVP_PKEY *evppkey = PEM_read_bio_PrivateKey(pkeyin, NULL, NULL, NULL);
		int ret2 = SSL_CTX_use_PrivateKey(ctx, evppkey);

		X509_free(x);
		EVP_PKEY_free(evppkey);
		BIO_free(pkeyin);
		BIO_free(certin);

		// Set the key and cert (note we use _chain_ to ensure clients are happy)
		SSL_CTX_set_ecdh_auto(ctx, 1);
		if (ret1 <= 0 || ret2 <= 0 || !SSL_CTX_check_private_key(ctx)) {
			ERR_print_errors_fp(stdout);
			return nullptr;
		}

		return ctx;
	}
};

int main(int argc, char **argv) {
	config_t cfg;
	config_init(&cfg);
	if (!config_read_file(&cfg, argv[1]))
		RET_ERR("Error reading config file");

	// Read config vars
	unsigned max_connections = 10, port = 8080;
	const char *tmp_;
	config_lookup_int(&cfg, "max-connections", (int*)&max_connections);
	config_lookup_int(&cfg, "port", (int*)&port);
	if (!config_lookup_string(&cfg, "password", &tmp_))
		RET_ERR("'password' missing in config file");
	master_pass = tmp_;
	if (!config_lookup_string(&cfg, "dir", &tmp_))
		RET_ERR("'dir' missing in config file");
	backup_dir = tmp_;
	
	// Read backup targets from config
	config_setting_t *targets_cfg = config_lookup(&cfg, "backup-targets");
	if (!targets_cfg)
		RET_ERR("Missing 'backup-targets' config array definition");
	int tgtcnt = config_setting_length(targets_cfg);
	if (!tgtcnt)
		RET_ERR("backup-targets must have at least one entry");

	for (int i = 0; i < tgtcnt; i++) {
		config_setting_t *entry = config_setting_get_elem(targets_cfg, i);
		config_setting_t *tgtname   = config_setting_get_member(entry, "name");
		config_setting_t *tgtmaxc   = config_setting_get_member(entry, "max-copies");
		config_setting_t *tgtrl     = config_setting_get_member(entry, "rate-limit");

		if (!tgtname || !tgtmaxc)
			RET_ERR("name and max-copies must be specified in each backup target entry");
		
		unsigned rl_period = 0, rl_copies = 0;
		if (tgtrl) {
			config_setting_t *mperiod = config_setting_get_member(tgtrl, "period");
			config_setting_t *mcopies = config_setting_get_member(tgtrl, "copies");
			if (mperiod && mcopies) {
				rl_period = (unsigned)config_setting_get_int(mperiod);
				rl_copies = (unsigned)config_setting_get_int(mcopies);
			}
		}

		targets[config_setting_get_string(tgtname)] = {
			.maxcopies = (unsigned)config_setting_get_int(tgtmaxc),
			.rl_period = rl_period,
			.rl_copies = rl_copies,
		};
	}
	std::cerr << "Parsed config, found " << targets.size() << " backup targets" << std::endl;

	int listendf = create_socket(port);

	// Drop privileges here if needed
	if (config_lookup_string(&cfg, "user", &tmp_)) {
		std::cout << "Dropping privileges to user " << tmp_ << std::endl;
		struct passwd * pw = getpwnam(tmp_);
		if (!pw) {
			std::cerr << "Could not find user in passwd file: " << tmp_ << std::endl;
			return 1;
		}

		if (setgid(pw->pw_gid) || setuid(pw->pw_uid)) {
			std::cerr << "setuid/setgid failed!" << std::endl;
			return 1;
		}
	}

	// Setup SSL stuff, use defaults mostly
	signal(SIGPIPE, SIG_IGN);
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	const char *keyfile_, *certfile_;
	if (!config_lookup_string(&cfg, "keyfile", &keyfile_) ||
	    !config_lookup_string(&cfg, "certfile", &certfile_))
	    RET_ERR("'keyfile' and 'certfile' are required to create SSL connections");

	SSLFactory factory(keyfile_, certfile_);

	// Handles incoming connections.
	std::list<std::unique_ptr<BackupHandler>> handlers;
	while (1) {
		struct sockaddr_in addr;
		socklen_t len = sizeof(addr);
		int clientfd = accept(listendf, (struct sockaddr*)&addr, &len);
		if (clientfd >= 0) {
			char ipstr[INET_ADDRSTRLEN] = {0};
			inet_ntop(AF_INET, &addr, ipstr, INET_ADDRSTRLEN);

			std::cout << "Got connection from " << ipstr << std::endl;
			// Set read/write timeout to something useful
			struct timeval to = { .tv_sec = 60, .tv_usec = 0 };
			setsockopt(clientfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&to, sizeof(to));
			setsockopt(clientfd, SOL_SOCKET, SO_SNDTIMEO, (char*)&to, sizeof(to));

			// Spawn a handler for this backup activity
			if (handlers.size() < max_connections) {
				SSL_CTX *ctx = factory.create();
				if (ctx) {
					SSL *ssl = SSL_new(ctx);
					SSL_set_fd(ssl, clientfd);
					handlers.emplace_back(new BackupHandler(clientfd, ssl, ctx));
				}
				else
					close(clientfd);
			}
			else
				close(clientfd);
		}

		// Take the chance to cleanup a bit dead threads.
		std::list<std::unique_ptr<BackupHandler>> newlist;
		for (auto & elem : handlers)
			if (!elem->eot())
				newlist.push_back(std::move(elem));
			else
				elem->join();
		handlers = std::move(newlist);
	}

	// Cleanup!
	close(listendf);
	EVP_cleanup();
}

