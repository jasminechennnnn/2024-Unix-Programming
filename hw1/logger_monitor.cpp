#include <iostream>
#include <string>

using namespace std;

#include <cstdlib> // system(), setenv()
#include <cstdio>

#include <unistd.h> // getopt()
#include <fcntl.h> // open()

void print_usage(const char* program_name) {
	printf("Usage: %s config.txt [-o file] [-p sopath] command [arg1 arg2 ...]\n", program_name);
	exit(EXIT_FAILURE);
}

int main(int argc, char** argv) {
	if (argc < 2) print_usage(argv[0]);
	setenv("CONFIG_FILE", argv[1], 1);

	const char* sopath = "./logger.so";
	const char* outfile = nullptr;
	int option; optind = 2; // start from argv[2]
	while ((option = getopt(argc, argv, "+o:p:")) != -1) {
		switch (option) {
			break; case 'o':
				outfile = optarg;
			break; case 'p':
				sopath = optarg;
			break; default:
				print_usage(argv[0]);
		}
	}
	if (optind == argc) print_usage(argv[0]);

	int fd = 2;
	if (outfile) fd = open(outfile, O_WRONLY | O_CREAT);
	char buffer[10];
	sprintf(buffer, "%i", fd);
	setenv("LOGGER_FD", buffer, 1);

	string cmd{"LD_PRELOAD="};
	cmd += sopath;
	for (int i = optind; i < argc; ++i) (cmd += ' ') += argv[i];
	//cerr << "[DEBUG] system(" << cmd << ")" << endl;
	int ret{system(cmd.c_str())};

	if (outfile) close(fd);

	return ret;
}
