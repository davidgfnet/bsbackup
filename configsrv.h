
#include <map>
#include <cerrno>
#include <string>

class ConfigServer {
public:
	static const unsigned name_size = 64;

	ConfigServer(const std::map<std::string, std::string> &files) {
		int reqfd[2], respfd[2];
		pid_t pid;
		if (pipe(reqfd) || pipe(respfd) || (pid = fork()) < 0) {
			perror("ConfigServer setup failed");
			exit(1);
		}
		if (pid) {
			reqfd_ = reqfd[1];
			respfd_ = respfd[0];
			close(reqfd[0]); close(respfd[1]);
		}
		else {
			// Serve clients here
			close(reqfd[1]); close(respfd[0]);
			while (1) {
				char name[name_size];
				if (!readall(reqfd[0], name, sizeof(name)))
					exit(1);
				name[sizeof(name)-1] = 0;

				// Read the whole file (if registered), then send size + contents
				std::string data;
				auto it = files.find(name);
				FILE *fd = it != files.end() ? fopen(it->second.c_str(), "rb") : NULL;
				if (fd) {
					char buf[1024];
					size_t r;
					while ((r = fread(buf, 1, sizeof(buf), fd)) > 0)
						data.append(buf, r);
					fclose(fd);
				}
				int sz = data.size();
				if (!writeall(respfd[1], &sz, sizeof(sz)) ||
				    !writeall(respfd[1], data.data(), data.size()))
					exit(1);
			}
		}
	}

	// Returns the contents of the file registered under 'name' (empty if none)
	std::string readfile(std::string name) {
		name.resize(name_size, 0);
		int sz = 0;
		if (!writeall(reqfd_, name.data(), name.size()) ||
		    !readall(respfd_, &sz, sizeof(sz)) || sz <= 0)
			return "";
		std::string resp(sz, 0);
		if (!readall(respfd_, &resp[0], sz))
			return "";
		return resp;
	}

private:

	static bool writeall(int fd, const void *buf, size_t len) {
		const char *p = (const char*)buf;
		while (len) {
			ssize_t w = write(fd, p, len);
			if (w < 0 && errno == EINTR)
				continue;
			if (w <= 0)
				return false;
			p += w;
			len -= w;
		}
		return true;
	}

	static bool readall(int fd, void *buf, size_t len) {
		char *p = (char*)buf;
		while (len) {
			ssize_t r = read(fd, p, len);
			if (r < 0 && errno == EINTR)
				continue;
			if (r <= 0)
				return false;
			p += r;
			len -= r;
		}
		return true;
	}

	int reqfd_, respfd_;
};

