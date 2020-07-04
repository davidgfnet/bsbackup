
class ConfigServer {
public:
	ConfigServer() {
		int reqfd[2], respfd[2];
		pipe(reqfd); pipe(respfd);
		if (fork()) {
			reqfd_ = reqfd[1];
			respfd_ = respfd[0];
			close(reqfd[0]); close(respfd[1]);
		}
		else {
			// Serve clients here
			close(reqfd[1]); close(respfd[0]);
			while (1) {
				char fname[1024];
				int fnsz = 0;
				while (fnsz < 1024) {
					int r = read(reqfd[0], &fname[fnsz], 1024 - fnsz);
					if (r <= 0)
						exit(1);
					fnsz += r;
				}
				
				// Read the file
				FILE * fd = fopen(fname, "rb");
				if (fd) {
					fseek(fd, 0, SEEK_END);
					int filesize = ftell(fd);
					fseek(fd, 0, SEEK_SET);
					write(respfd[1], &filesize, sizeof(filesize));
					
					for (int i = 0; i < filesize; i += 1024) {
						char buf[1024];
						fread(buf, 1, sizeof(buf), fd);
						write(respfd[1], buf, std::min(filesize - i, 1024));
					}
					fclose(fd);
				}
				else {
					int nofile = 0;
					write(respfd[1], &nofile, sizeof(nofile));
				}
			}
		}
	}

	std::string readfile(std::string fn) {
		while (fn.size() < 1024)
			fn.push_back(0);
		write(reqfd_, fn.c_str(), fn.size());
		
		// Wait for response
		std::string resp;
		int sz;
		read(respfd_, &sz, sizeof(sz));
		while (sz > 0) {
			char tmp[1024];
			int r = read(respfd_, tmp, std::min(sz, 1024));
			if (r <= 0)
				return resp;
			resp += std::string(tmp, r);
			sz -= r;
		}
		return resp;
	}

private:
	int reqfd_, respfd_;
};


