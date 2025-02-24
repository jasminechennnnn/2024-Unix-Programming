#include <iostream>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <string>
#include <vector>
#include <map>
#define fi first
#define se second
#include <tuple>
#include <algorithm>

#include <cstdio> // perror(), setvbuf()
#include <cstdlib> // exit()
#include <cstdint>
#include <cstring> // strdup()
#include <cassert>

#include <unistd.h> // fork(), execvp()
#include <sys/ptrace.h> // ptrace()
#include <sys/wait.h> // waitpid()
#include <sys/user.h> // struct user_regs_struct

#include <elf.h>

#include <capstone/capstone.h>

using namespace std;

// tackle the return type (unsigned long) of ptrace :(
class BytesOrWord {
	unsigned long _word;
public:
	BytesOrWord()=default;
	BytesOrWord(unsigned long other) : _word{other} {}
	BytesOrWord& operator=(unsigned long other) { _word = other; return *this; }
	operator unsigned long() { return _word; }

    // allow indexing bytes in a word
	uint8_t& operator[](int i) {
		assert(clamp(i, 0, 7) == i);
		return reinterpret_cast<uint8_t*>(&_word)[i];
	}
};
istream& operator>>(istream& is, BytesOrWord& w) {
	unsigned long t;
	is >> t;
	w = t;
	return is;
}
static BytesOrWord bow{};

const int MxInsSz{15}; // max instruction bytes

static pid_t child{0};
static int status;
static unsigned long text_start, text_size;
struct user_regs_struct regs;

static map<unsigned long, uint8_t> break_points{}; // for break {address : original byte content}
static map<int, unsigned long> id{}; // for info break {index : break point address}

//////////////////////////////////////////////////////////////////////////

void errexit(const char* s) {
	perror(s);
	exit(EXIT_FAILURE);
}

class _x86_disassembler {
    inline char hex(uint8_t x) { return x < 10 ? ('0' + x) : ('a' + x - 10); }
	inline string b2h(uint8_t b) { return string{hex(b / 16)} + hex(b % 16); }   
    csh handle;

public:
	_x86_disassembler() {
		if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) errexit("cs_open() failed");
	}
	~_x86_disassembler() {
		cs_close(&handle);
	}
	vector<tuple<unsigned long, string, string>> operator()(const uint8_t* code, size_t size, unsigned long address, size_t count) {
		cs_insn* insn;
		count = cs_disasm(handle, code, size, address, count, &insn);
		vector<tuple<unsigned long, string, string>> v{};
		for (size_t i{0}; i < count; i++) {
			string t{};
			for (int j{0}; j < insn[i].size; ++j) t += b2h(insn[i].bytes[j]) + ' ';
			v.emplace_back(
				insn[i].address,
				t,
				string{insn[i].mnemonic} + "\t" + insn[i].op_str
			);
		}
		cs_free(insn, count);
		return v;
	}
} x86_disassembler;

static void print_asm(unsigned long address, size_t count = 5) {
    // extract 5 lines machine code and put them into a vector<uint8_t>
	vector<uint8_t> data{};
	if (clamp(address, text_start, text_start + text_size - 1) == address) {
		for (unsigned long i{address}; i < min(text_start + text_size, address + count * MxInsSz); i += sizeof(long)) {
			errno = 0;
			bow = ptrace(PTRACE_PEEKDATA, child, i, 0L);
			if (errno) errexit("PTRACE_PEEKDATA FAILED");
			for (unsigned long j{0}; j < sizeof(long) && i + j < text_start + text_size; ++j) data.push_back(bow[j]);
		}
	}
    // 0xcc (break instructions) should be restore for print
	for (auto& [k, v] : break_points) {
		if (clamp(k, address, address + data.size() - 1) == k) data[k - address] = v;
	}

    // call disassembler
	auto assembly{x86_disassembler(data.data(), data.size(), address, count)};
	cout << noshowbase << left;
	for (auto& [addr, code, asmby] : assembly) {
		cout << "\t" << addr << ": " << setfill(' ') << setw(3 * MxInsSz) << code << " " << asmby << '\n';
	}
	if (assembly.size() < 5) cout << "** the address is out of the range of the text section.\n";
	cout << showbase << right << flush;
}

void load_program(char** argv) {
    // get entry point of the program (typically equals to the addr of the text section)
    ifstream elf{argv[0], ios_base::in | ios_base::binary};
    
    // read elf_header for section header addr, section header size
    Elf64_Ehdr elf_header;
    elf.read(reinterpret_cast<char*>(&elf_header), sizeof(elf_header));

    // read all section headers
    elf.seekg(elf_header.e_shoff, ios_base::beg);
    vector<Elf64_Shdr> section_headers(elf_header.e_shnum);
    elf.read(reinterpret_cast<char*>(section_headers.data()), elf_header.e_shnum * sizeof(Elf64_Shdr));

    // read string section data (vector<char>)
    elf.seekg(section_headers[elf_header.e_shstrndx].sh_offset, ios_base::beg);
    vector<char> string_table(section_headers[elf_header.e_shstrndx].sh_size);
    elf.read(string_table.data(), section_headers[elf_header.e_shstrndx].sh_size);

    // get text_start, text_size
    for (auto& sh : section_headers) {
        if (".text"s == &string_table[sh.sh_name]) {
            text_start = sh.sh_addr;
            text_size = sh.sh_size;
            break;
        }
    }

    // fork() tracked program and enable PTRACE
    child = fork();
    if (child < 0) errexit("fork() failed");
    if (child == 0) {
        if (ptrace(PTRACE_TRACEME, 0, 0L, 0L) < 0) errexit("PTRACE_TRACEME failed"); 
        if (execvp(argv[0], argv) < 0) errexit("execvp() failed");
    } else {
        if (waitpid(child, &status, 0) < 0) errexit("waitpid() failed"); // execvp()
        if (ptrace(PTRACE_SETOPTIONS, child, 0L, PTRACE_O_EXITKILL) < 0) errexit("PTRACE_SETOPTIONS failed");
        if (ptrace(PTRACE_GETREGS, child, 0L, &regs) < 0) errexit("PTRACE_GETREGS failed");
    
    // get real text_start for x86_disassembler to extract code
        text_start += regs.rip - elf_header.e_entry;

        cout << "** program '" << argv[0] << "' loaded. entry point " << regs.rip << "." << endl;
        // cout << "text_start = " << text_start << "\n text_size = " << text_size << endl; 
        print_asm(regs.rip);     
    }
}

int main(int argc, char** argv) {
	if (setvbuf(stdin, nullptr, _IONBF, 0)) errexit("setvbuf()");
	cout << showbase << hex;
	if (argc > 1) load_program(argv + 1);

    auto prompt{[] {
        cout << "(sdb) " << flush;
        string s{};
        if (!getline(cin, s)) errexit("EOF");
        cout << "[sdb] " << s << endl; //
        return istringstream{s};
	}};

    // inject & restore 0xcc for breakpoints
	auto put_bp{[&](unsigned long addr, bool flag = false) {
		if (!flag) { // edited ?
			errno = 0;
			bow = ptrace(PTRACE_PEEKDATA, child, addr, 0L);
			if (errno) errexit("PTRACE_PEEKDATA FAILED");
		}
		uint8_t ret{bow[0]}; // org content
		bow[0] = 0xCC;
		if (ptrace(PTRACE_POKEDATA, child, addr, bow) < 0) errexit("PTRACE_POKEDATA FAILED");
		return ret;
	}};
	auto take_bp{[](unsigned long addr, uint8_t org, bool flag = false) {
		if (!flag) {
			errno = 0;
			bow = ptrace(PTRACE_PEEKDATA, child, addr, 0L);
			if (errno) errexit("PTRACE_PEEKDATA FAILED");
		}
		bow[0] = org;
		if (ptrace(PTRACE_POKEDATA, child, addr, bow) < 0) errexit("PTRACE_POKEDATA FAILED");
	}};

	while (child == 0) {
		string op{};
		auto ss{prompt()};
		ss >> op;
		if (op == "load") {
			vector<char*> a{};
			while (ss >> op) a.push_back(strdup(op.c_str()));
			if (a.empty()) errexit("Command format wrong.");
			a.push_back(nullptr);

			load_program(a.data());

			for (auto& x : a) free(x);
		} else {
			cout << "** please load a program first." << endl;
		}
	}

	while (WIFSTOPPED(status)) {
		string op{};
		auto ss{prompt()};
		ss >> op;
		if (op == "si") {
			if (ptrace(PTRACE_GETREGS, child, 0L, &regs) < 0) errexit("PTRACE_GETREGS failed");
			auto it{break_points.find(regs.rip)};
			if (it != break_points.end()) take_bp(regs.rip, it->se);

			if (ptrace(PTRACE_SINGLESTEP, child, 0L, 0l) < 0) errexit("PTRACE_SINGLESTEP failed");
			if (waitpid(child, &status, 0) < 0) errexit("waitpid() failed");
			if (!WIFSTOPPED(status)) break;

			if (it != break_points.end()) put_bp(regs.rip, true);
			if (ptrace(PTRACE_GETREGS, child, 0L, &regs) < 0) errexit("PTRACE_GETREGS failed");
			if (break_points.count(regs.rip)) {
				cout << "** hit a breakpoint at " << regs.rip << "." << endl;
			}
			print_asm(regs.rip);
		} else if (op == "cont" || op == "syscall") {
			if (ptrace(PTRACE_GETREGS, child, 0L, &regs) < 0) errexit("PTRACE_GETREGS failed");
			auto it{break_points.find(regs.rip)};
			if (it != break_points.end()) {
				take_bp(regs.rip, it->se);

				if (ptrace(PTRACE_SINGLESTEP, child, 0L, 0l) < 0) errexit("PTRACE_SINGLESTEP failed");
				if (waitpid(child, &status, 0) < 0) errexit("waitpid() failed");
				if (!WIFSTOPPED(status)) break;

				put_bp(regs.rip, true);
			}

			if (ptrace(op == "cont" ? PTRACE_CONT : PTRACE_SYSCALL, child, 0L, 0l) < 0) errexit("PTRACE_CONT failed");
			if (waitpid(child, &status, 0) < 0) errexit("waitpid() failed");
			if (!WIFSTOPPED(status)) break;

			if (ptrace(PTRACE_GETREGS, child, 0L, &regs) < 0) errexit("PTRACE_GETREGS failed");
			if (break_points.count(regs.rip - 1)) {
				regs.rip -= 1;
				if (ptrace(PTRACE_SETREGS, child, 0L, &regs) < 0) errexit("PTRACE_SETREGS FAILED");

				cout << "** hit a breakpoint at " << regs.rip << "." << endl;
				print_asm(regs.rip);
			} else {
				struct __ptrace_syscall_info info;
                if (ptrace(PTRACE_GET_SYSCALL_INFO, child, sizeof(info), &info) < 0) errexit("PTRACE_GET_SYSCALL_INFO");

				static int sc_nr; // syscall number
                // sc_nr = info.entry.nr;
                // cout << "** a syscall(" << dec << sc_nr << hex << ") at " << (regs.rip - 2) << "." << endl;

                if (info.op == PTRACE_SYSCALL_INFO_ENTRY) {
					sc_nr = info.entry.nr;
					cout << "** enter a syscall(" << dec << sc_nr << hex << ") at " << (regs.rip - 2) << "." << endl;
				} else if (info.op == PTRACE_SYSCALL_INFO_EXIT) {
					cout << "** leave a syscall(" << dec << sc_nr << hex << ") = ";
					cout << dec << info.exit.rval << hex << " at " << (regs.rip - 2) << "." << endl;
				}
                print_asm(regs.rip - 2);
			}
		} else if (op == "break") {
			unsigned long addr;
			if (!(ss >> hex >> addr)) errexit("Command format wrong.");
			if (break_points.count(addr)) continue;

			static int cnt{0};
			id[cnt++] = addr;
			break_points[addr] = put_bp(addr);

			cout << "** set a breakpoint at " << addr << "." << endl;
		} else if (op == "info") {
			if (!(ss >> op)) errexit("Command format wrong.");

			if (op == "reg") {
				if (ptrace(PTRACE_GETREGS, child, 0L, &regs) < 0) errexit("PTRACE_GETREGS failed");
				char c{cout.fill()}; cout << noshowbase << setfill('0');
                c = ' ';
				cout << "$rax 0x" << setw(16) << regs.rax << "    ";
				cout << "$rbx 0x" << setw(16) << regs.rbx << "    ";
				cout << "$rcx 0x" << setw(16) << regs.rcx << "\n";
				cout << "$rdx 0x" << setw(16) << regs.rdx << "    ";
				cout << "$rsi 0x" << setw(16) << regs.rsi << "    ";
				cout << "$rdi 0x" << setw(16) << regs.rdi << "\n";
				cout << "$rbp 0x" << setw(16) << regs.rbp << "    ";
				cout << "$rsp 0x" << setw(16) << regs.rsp << "    ";
				cout << "$r8  0x" << setw(16) << regs.r8  << "\n";
				cout << "$r9  0x" << setw(16) << regs.r9  << "    ";
				cout << "$r10 0x" << setw(16) << regs.r10 << "    ";
				cout << "$r11 0x" << setw(16) << regs.r11 << "\n";
				cout << "$r12 0x" << setw(16) << regs.r12 << "    ";
				cout << "$r13 0x" << setw(16) << regs.r13 << "    ";
				cout << "$r14 0x" << setw(16) << regs.r14 << "\n";
				cout << "$r15 0x" << setw(16) << regs.r15 << "    ";
				cout << "$rip 0x" << setw(16) << regs.rip << "    ";
				cout << "$eflags 0x" << setw(16) << regs.eflags << "\n";
				cout << showbase << setfill(c) << flush;
			} else if (op == "break") {
				if (!break_points.empty()) {
					cout << left;
					cout << "Num     Address\n";
					for (auto& [k, v] : id) cout << dec << setw(8) << k << hex << v << '\n';
					cout << right << flush;
				} else {
					cout << "** no breakpoints." << endl;
				}
			} else errexit("Command format wrong.");
		} else if (op == "delete") {
			int i;
			if (!(ss >> i)) errexit("Command format wrong.");

			auto it1{id.find(i)};
			if (it1 == id.end()) {
				cout << "** breakpoint " << i << " does not exist." << endl;
				continue;
			}
			auto it2{break_points.find(it1->se)};
			take_bp(it1->se, it2->se);
			break_points.erase(it2);
			id.erase(it1);
		} else if (op == "patch") {
			unsigned long addr, len;
			BytesOrWord data{};
			if (!(ss >> hex >> addr >> data >> len)) errexit("Command format wrong.");

			if (len < sizeof(long)) {
				errno = 0;
				bow = ptrace(PTRACE_PEEKDATA, child, addr, 0L);
				if (errno) errexit("PTRACE_PEEKDATA FAILED");
			}
			for (unsigned long i{0}; i < len; ++i) {
				auto it{break_points.find(addr + i)};
				if (it != break_points.end()) {
					it->se = data[i];
					bow[i] = 0xCC;
				} else bow[i] = data[i];
			}
			if (ptrace(PTRACE_POKEDATA, child, addr, bow) < 0) errexit("PTRACE_POKEDATA FAILED");
            cout << "** patch memory at address " << addr << "." << endl;
		} else if (op != "") {
            cout << "Command not found." << endl; 
            // errexit("Command not found.");
        }
	}
	assert(WIFEXITED(status));
	cout << "** the target program terminated." << endl;
}
