#include <fcntl.h> // open()
#include <unistd.h> // write()

#include <cstdio> // fopen(), fread(), fwrite()
#include <sys/socket.h> // connect()
#include <netdb.h> // getaddrinfo()
#include <cstdlib> // system(), getenv()
#include <cerrno>
#include <dlfcn.h> // dlsym()
#include <unistd.h> // getpid()
#include <arpa/inet.h> // inet_ntop()
#include <cstring> // memset()

#include <iostream>
#include <sstream>
#include <fstream>
#include <filesystem>
#include <vector>
#include <string>
#include <map>
#include <array>
#include <algorithm>
#include <regex>

using namespace std;
namespace fs = filesystem;

// used to store real errno
static int errod;

// api function types
using fopen_t = FILE*(const char*, const char*);
using fread_t = size_t(void*, size_t, size_t, FILE*);
using fwrite_t = size_t(const void*, size_t, size_t, FILE*);
using connect_t = int(int, const struct sockaddr*, socklen_t);
using getaddrinfo_t = int(const char*, const char*, const struct addrinfo*, struct addrinfo**);
using system_t = int(const char*);

// wrappers
extern "C" fopen_t fopen;
extern "C" fread_t fread;
extern "C" fwrite_t fwrite;
extern "C" connect_t connect;
extern "C" getaddrinfo_t getaddrinfo;
extern "C" system_t system;

// "real" functions
static fopen_t* fopen_real = (fopen_t*)dlsym(RTLD_NEXT, "fopen");
static fread_t* fread_real = (fread_t*)dlsym(RTLD_NEXT, "fread");
static fwrite_t* fwrite_real = (fwrite_t*)dlsym(RTLD_NEXT, "fwrite");
static connect_t* connect_real = (connect_t*)dlsym(RTLD_NEXT, "connect");
static getaddrinfo_t* getaddrinfo_real = (getaddrinfo_t*)dlsym(RTLD_NEXT, "getaddrinfo");
static system_t* system_real = (system_t*)dlsym(RTLD_NEXT, "system");

// states
static map<FILE*, string> fp_name{{stdin, "stdin"}, {stdout, "stdout"}, {stderr, "stderr"}};

// config
static map<string, vector<string>> config{[] {
	string config_file{getenv("CONFIG_FILE")};

	map<string, vector<string>> mp{};
	ifstream fs{config_file};
	for (string line{}; getline(fs, line); ) {
		if (!line.compare(0, 6, "BEGIN ")) {
			string func{line.substr(6, line.find("-blacklist") - 6)};
			while (getline(fs, line)) {
				if (!line.compare(0, 4, "END ")) break;
				mp[func].push_back(line);
			}
		}
	}

	return mp;
}()};

#define DEBUGGER(s) { write(2, s, sizeof(s)); }

static inline void logger(const string& s) {
	write(stoi(getenv("LOGGER_FD")), s.c_str(), s.length());
}

static int pid{getpid()};

static inline string get_logname(const string& filename) {
	return fs::path{filename}.filename().replace_extension().string();
}
static inline string fread_logname(const string& filename) {
	return to_string(pid) + "-" + get_logname(filename) + "-read.log";
}
static inline string fwrite_logname(const string& filename) {
	return to_string(pid) + "-" + get_logname(filename) + "-write.log";
}

static vector<fs::path> matched_paths(const string& s) {
	vector<fs::path> ret{};
	fs::path p{fs::absolute(s)};
	if (p.filename().string().find('*') != string::npos) {
		string _rgx{};
		for (auto& c : p.filename().string()) {
			switch (c) {
				break; case '*': _rgx += ".*";
				break; case '.': _rgx += "\\.";
				break; default: _rgx += c;
			}
		}
		regex rgx{_rgx};
		for (const auto& entry : fs::directory_iterator(p.parent_path())) {
			if (!regex_match(entry.path().filename().string(), rgx)) continue;
			ret.push_back(entry.path());
		}
	} else ret.push_back(p);
	return ret;
}

FILE* fopen(const char* filename, const char* mode) {
	//DEBUGGER("[DEBUG] fopen()\n");

	bool flag{false}; FILE* ret;
	for (auto& x : config["open"])
		for (auto& y : matched_paths(x))
			if (fs::exists(filename) && fs::equivalent(y, filename)) {
				flag = true, ret = NULL;
				break;
			}
	if (!flag) { // valid
		ret = fopen_real(filename, mode), errod = errno;
	}

	if (ret) {
		fp_name[ret] = filename;
	}

	ostringstream ss{};
	ss << "[logger] fopen(\"" << filename << "\", \"" << mode << "\") = ";
	if (ret) ss << ret;
	else ss << "0x0";
	ss << endl;
	logger(ss.str());

	errno = flag ? EACCES : errod; // If the filename is in the blacklist, return NULL and set errno to EACCES. 
	return ret;
}

size_t fread(void* buffer, size_t size, size_t count, FILE* stream) {
	//DEBUGGER("[DEBUG] fread()\n");
	const string& filename{fp_name[stream]};

	bool flag{false};
	long pos{ftell(stream)};

	size_t ret{fread_real(buffer, size, count, stream)}; errod = errno;
	// ((char*)buffer)[ret] = '\0';

	string s{};
	for (int i{0}; i < ret * size; ++i) s += ((char*)buffer)[i];
	for (auto& x : config["read"])
		if (s.find(x) != string::npos) {
			flag = true;
			break;
		}
	if (flag) {
		memset(buffer, 0, ret * size);
		ret = 0;
		fseek(stream, pos, SEEK_SET);
	} else {
		FILE* log{fopen_real(fread_logname(filename).c_str(), "a")};
		fwrite_real(buffer, size, ret, log);
		fclose(log);
	}

	ostringstream ss{};
	ss << "[logger] fread(" << buffer << ", " << size << ", " << count << ", " << stream << ") = " << ret << endl;
	logger(ss.str());

	errno = flag ? EIO : errod;
	return ret;
}

static const array<const char*, 255> raw_table{[] {
	array<const char*, 255> t{};
	t['\0'] = R"(\0)";
	t['\a'] = R"(\a)";
	t['\b'] = R"(\b)";
	t['\t'] = R"(\t)";
	t['\n'] = R"(\n)";
	t['\v'] = R"(\v)";
	t['\f'] = R"(\f)";
	t['\r'] = R"(\r)";
	return t;
}()};

static string convert_to_raw(const char* str, size_t len) {
	string ret{};
	for (int i{0}; ; ++i) {
		unsigned char c{str[i]};
		if (!c) break;
		if (raw_table[c]) ret += raw_table[c];
		else ret += c;
	}
	return ret;
}

size_t fwrite(const void* buffer, size_t size, size_t count, FILE* stream) {
	//DEBUGGER("[DEBUG] fwrite()\n");
	const string& filename{fp_name[stream]};

	bool flag{false}; size_t ret;
	for (auto& x : config["write"])
		for (auto& y : matched_paths(x))
			if (fs::exists(filename) && fs::equivalent(y, filename)) {
				flag = true, ret = 0;
				break;
			}
	if (!flag) {
		ret = fwrite_real(buffer, size, count, stream), errod = errno;

		FILE* log{fopen_real(fwrite_logname(filename).c_str(), "a")};
		fwrite_real(buffer, size, count, log);
		fclose(log);
	}

	ostringstream ss{};
	ss << "[logger] fwrite(\"" << convert_to_raw((const char*)buffer, ret * size) << "\", " << size << ", " << count << ", " << stream << ") = " << ret << endl;
	logger(ss.str());

	errno = flag ? EACCES : errod;
	return ret;
}

int connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen) {
	//DEBUGGER("[DEBUG] connect()\n");

	char addr_ip[INET_ADDRSTRLEN >= INET6_ADDRSTRLEN ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN];
	if (addr->sa_family == AF_INET) { // IPv4
		const struct sockaddr_in* addr_in{(const struct sockaddr_in*)addr};
		inet_ntop(AF_INET, &(addr_in->sin_addr), addr_ip, INET_ADDRSTRLEN);
	} else if (addr->sa_family == AF_INET6) { // IPv6
		const struct sockaddr_in6* addr_in6{(const struct sockaddr_in6*)addr};
		inet_ntop(AF_INET6, &(addr_in6->sin6_addr), addr_ip, INET6_ADDRSTRLEN);
	}

	bool flag{false}; int ret;
	for (auto x : config["connect"])
		if (x == addr_ip) {
			flag = true, ret = -1;
			break;
		}
	if (!flag) {
		ret = connect_real(sockfd, addr, addrlen), errod = errno;
	}

	ostringstream ss{};
	ss << "[logger] connect(" << sockfd << ", \"" << addr_ip << "\", " << addrlen << ") = " << ret << endl;
	logger(ss.str());

	errno = flag ? ECONNREFUSED : errod;
	return ret;
}

int getaddrinfo(const char* node, const char* service, const struct addrinfo* hints, struct addrinfo** res) {
	//DEBUGGER("[DEBUG] getaddrinfo()\n");

	bool flag{false}; int ret; errod = errno;
	for (auto& x : config["getaddrinfo"])
		if (x == node) {
			flag = true, ret = EAI_NONAME;
			break;
		}
	if (!flag) {
		ret = getaddrinfo_real(node, service, hints, res), errod = errno;
	}

	ostringstream ss{};
	ss << "[logger] getaddrinfo(";
	if (node) ss << '"' << node << '"';
	else ss << "(nil)";
	ss << ", ";
	if (service) ss << '"' << service << '"';
	else ss << "(nil)";
	ss << ", " << hints << "," << res << ") = " << ret << endl;
	logger(ss.str());

	errno = flag ? errno : errod;
	return ret;
}

int system(const char* command) {
	//DEBUGGER("[DEBUG] system()\n");

	int ret{system_real(command)}; errod = errno;

	ostringstream ss{};
	ss << "[logger] system(\"" << command << "\") = " << ret << endl;
	logger(ss.str());

	errno = errod;
	return ret;
}
