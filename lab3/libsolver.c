#include <stdio.h> // fopen(), fclose(), getline(), sscanf(), sprintf()
#include <stdlib.h> // malloc(), free(), exit(), EXIT_FAILURE
#include <stdbool.h>
#include <string.h>

#include <unistd.h> // sysconf()
#include <sys/mman.h> // mprotect()
#include <dlfcn.h> // dlopen(), dlsym()

#include "libmaze.h"
#include "got2.h"

typedef struct {
    int x, y;         // (x, y)
    int parent_index;
    int dir;          // how does previous node get to here? (0, 1, 2, 3) = (up, down, left, right) 
} node_t;

bool is_valid(maze_t* maze, int x, int y) {
    return x >= 0 && x < maze->w && y >= 0 && y < maze->h && maze->blk[y][x] == 0;
}

int moves[1200];

// BFS
void solve_maze(maze_t* maze, int* len) {
    printf("start to solve maze...\n");
    static int dirx[] = {0, 0, -1, 1};
    static int diry[] = {-1, 1, 0, 0};
    int start_x = maze->sx, start_y = maze->sy;
    int end_x = maze->ex, end_y = maze->ey;

    bool visited[_MAZE_MAXY][_MAZE_MAXX];
    memset(visited, false, sizeof(visited));
    visited[start_y][start_x] = true;

    // circular array queue + BFS
    node_t* queue = (node_t*)malloc(_MAZE_MAXY * _MAZE_MAXX * sizeof(node_t));
    int front = 0, rear = 0;
    queue[rear++] = (node_t){start_x, start_y, -1, -1}; // -1 = init node
    
    while (front != rear) {
        node_t current = queue[front++];
        if (front >= _MAZE_MAXY * _MAZE_MAXX) front = 0; // circular

        // Goal
        if (current.x == end_x && current.y == end_y) {
            *len = 0;
            while (current.parent_index != -1) {
                //printf("current = %d\n", current.dir);
                moves[(*len)++] = current.dir;
                current = queue[current.parent_index];
            }
            free(queue);
            return ;
        }

        // try 4 directions
        for (int i = 0; i < 4; ++i) {
            int nx = current.x + dirx[i];
            int ny = current.y + diry[i];
            if (is_valid(maze, nx, ny) && !visited[ny][nx]) {
                visited[ny][nx] = true;
                queue[rear++] = (node_t){nx, ny, front - 1, i};
                if (rear >= _MAZE_MAXY * _MAZE_MAXX) rear = 0;
            }
        }
    }
    free(queue);
    return ;
}

void print_maze(maze_t* maze) {
    for (int x = 0; x < maze->w; ++x) {
        for (int y = 0; y < maze->h; ++y) {
            if (x != 0 && x != maze->w - 1 && y != 0 && y != maze->h - 1) continue;
            printf("(%d, %d) = %d\n", x, y, maze->blk[y][x]);
        }
        printf("\n");
    }

}

static void* get_base() {
	FILE* fd = fopen("/proc/self/maps", "r");
    printf("fd of /proc/self/maps = %p\n", fd);
    
	if(!fd) exit(EXIT_FAILURE);
	char* line = NULL; size_t len;
	while ((getline(&line, &len, fd)) != -1) {
		if (strstr(line, "/maze") == NULL) continue;
		void* base;
		if (sscanf(line, "%p", &base) != 1) exit(EXIT_FAILURE);
		free(line), fclose(fd);
		return base;
	}
	free(line), fclose(fd);
	exit(EXIT_FAILURE);
}

void cat(const char* filename) {
    FILE* fp = fopen(filename, "r");
    char c;
    while (fread(&c, sizeof(char), 1, fp) == 1) fwrite(&c, sizeof(char), 1, stdout);
    fclose(fp);
}

int maze_init() {
    printf("UP112_GOT_MAZE_CHALLENGE\n");
    void* main_ptr = maze_get_ptr();
    printf("SOLVER: _main = %p\n", main_ptr);

	int pagesize = sysconf(_SC_PAGE_SIZE);
	if (pagesize == -1) exit(EXIT_FAILURE);
   
    void* base = main_ptr - 0x1b7a9;
    printf("base = %p\n", base);

    // get address of move functions
    void* move_functions[4];
    move_functions[0] = dlsym(RTLD_DEFAULT, "move_up");
    move_functions[1] = dlsym(RTLD_DEFAULT, "move_down");
    move_functions[2] = dlsym(RTLD_DEFAULT, "move_left");
    move_functions[3] = dlsym(RTLD_DEFAULT, "move_right");

    // for (int i = 0; i < 4; ++i) printf("move_functions %d = %p\n", i, move_functions[i]);

    // solve maze
    maze_t* maze = maze_load("/maze.txt"); // function form libmaze.h
    int move_len;
    solve_maze(maze, &move_len);
    printf("move_len = %d\n", move_len);
    fflush(stdout), fflush(stderr);

    // fix GOT offset
    int ck[1000] = {};
    for (int i = 0; i < move_len; ++i) {
        int n_page = got[i] / pagesize;
        // set protection on a region of memory, PROT_WRITE: The memory can be modified.
		if (!ck[n_page]) {
			if (mprotect(base + n_page * pagesize, pagesize, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) _exit(1);
			ck[n_page] = 1;
			// fprintf(stderr, "mprotect = %p\n", base + n_page * pagesize);
		}
        fflush(stderr);

        // printf("moves %d = %d\n", i, moves[move_len - 1 - i]);
        memcpy(base + got[i], &move_functions[moves[move_len - 1 - i]], sizeof(void*));
    }

    fflush(stdout);
    maze_free(maze);  // function form libmaze.h

    printf("my solver done===============\n");
    //cat("/proc/self/maps");
    fflush(stdout), fflush(stderr);
    return 0;
}
