#include "Quissh.h"
#include <cstring>


#define HOST "192.168.0.10"
#define PORT 22
#define LOCAL_FILE "example.txt"
#define REMOTE_PATH "/tmp/example.txt"

int main()
{
#if 0
	SSH::AuthVar authdata = SSH::PasswdAuth{"user123", "pass123"};
#else
	Quissh::AuthVar authdata = Quissh::PubkeyAuth{};
#endif

	char const *data = "Hello, world";
	int offset = 0;
	int length = strlen(data);

	auto Reader = [&data, &offset, length](char *ptr, int len) {
		if (offset < length) {
			int n = std::min(len, length - offset);
			memcpy(ptr, data + offset, n);
			offset += n;
			return n;
		}
		return 0;
	};

	auto Writer = [](char const *ptr, int len) {
		return fwrite(ptr, 1, len, stdout);
	};

	Quissh ssh;
	ssh.open(HOST, PORT, authdata);
	ssh.exec("uname -a", Writer);
	Quissh::SFTP sftp(ssh);
	if (sftp.open()) {
		auto r = sftp.ls(".");
		if (r) {
			for (Quissh::FileAttribute const &atts : *r) {
				puts(atts.name.c_str());
			}
		}
		sftp.mkdir("hogehoge");
		sftp.rmdir("hogehoge");
		sftp.push("example.txt", Reader);
		sftp.pull("example.txt", Writer);
		sftp.close();
	}
	return 0;
}

