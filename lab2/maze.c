#include <linux/module.h> // module_init(), module_exit()
#include <linux/init.h> // __init, __exit
#include <linux/kern_levels.h> // KERN_INFO
#include <linux/device/class.h> // struct class, class_create(), class_destroy()
#include <linux/types.h> // dev_t
#include <linux/cdev.h> // struct cdev, cdev_init(), cdev_add(), cdev_del()
#include <linux/fs.h> // struct file_operations, struct inode, struct file, alloc_chrdev_region(), unregister_chrdev_region(), iminor()
#include <linux/device.h> // device_create(), device_destroy()
#include <linux/slab.h> // kzalloc(), krealloc(), kfree()
#include <linux/mm_types.h> // struct vm_area_struct
#include <linux/mm.h> // SetPageReserved(), ClearPageReserved(), remap_pfn_range()
#include <linux/proc_fs.h> // struct proc_ops
#include <linux/seq_file.h> // single_open(), seq_printf()
#include <linux/slab.h>	// kmalloc(), kfree()
#include <linux/random.h> // __get_random_u32_below();

#include "maze.h"
#define MAZE_DEV_CNT 1

static dev_t devnum;
static struct cdev m_cdev; // a character device
static struct class *m_class; // a class of devices in the sysfs filesystem

pid_t pids[_MAZE_MAXUSER] = {-1, -1, -1}; // store pids of processes had created maze 
bool maze_created[_MAZE_MAXUSER] = {0, 0, 0};
coord_t maze_size[_MAZE_MAXUSER];
coord_t start_pos[_MAZE_MAXUSER];
coord_t end_pos[_MAZE_MAXUSER];
coord_t player_pos[_MAZE_MAXUSER];
bool mazes[_MAZE_MAXUSER][_MAZE_MAXX][_MAZE_MAXY];

static int maze_dev_open(struct inode *i, struct file *f) {
	printk(KERN_INFO "maze: device opened.\n");
	return 0;
}

static ssize_t maze_dev_read(struct file *f, char __user *buf, size_t len, loff_t *off) {
	
	int index;
	for (index = 0; index < _MAZE_MAXUSER; ++ index) if (pids[index] == current->pid) break;
	if (index == _MAZE_MAXUSER) return -EBADFD;

 	int rows = maze_size[index].y;
	int cols = maze_size[index].x;
	int size = rows * cols * sizeof(char);

	char *data = kmalloc(size, GFP_KERNEL);
	// printk("copy size = %d", size);

	if (!data) return -ENOMEM;
	for (int i = 0; i < rows; ++i) {
    	for (int j = 0; j < cols; ++j) 
        	*(data + i * cols + j) = (char)mazes[index][i][j];
	}
	if (copy_to_user((char __user *)buf, data, size)) {
		kfree(data);
		return -EBUSY;
	}
	kfree(data);
	return size;
}

static ssize_t maze_dev_write(struct file *f, const char __user *buf, size_t len, loff_t *off) {
	// printk(KERN_INFO "maze: write %zu bytes @ %llu.\n", len, *off);

	int index;
	for (index = 0; index < _MAZE_MAXUSER; ++ index) if (pids[index] == current->pid) break;
	if (index == _MAZE_MAXUSER) return -EBADFD;

	int num_moves = len / sizeof(coord_t);
	coord_t *moves = kmalloc(num_moves * sizeof(coord_t), GFP_KERNEL);
    if (!moves) return -ENOMEM; 
	if (copy_from_user(moves, (coord_t __user *)buf, len)) {
        kfree(moves);
        return -EBUSY;
    }

	for (int i = 0; i < num_moves; ++i) {
		if (moves[i].x > 1 || moves[i].x < -1 || moves[i].y > 1 || moves[i].y < -1) continue;

		int new_x = player_pos[index].x + moves[i].x;
        int new_y = player_pos[index].y + moves[i].y;
        if(new_x < 0 || new_y < 0 || new_x >= maze_size[index].x || new_y >= maze_size[index].y) continue;
		if(mazes[index][new_y][new_x] != 0) continue;
		// printk("valid move (%d, %d) from /dev write! @ (%d, %d)\n", moves[i].x, moves[i].y, new_x, new_y);
		player_pos[index].x = new_x;
		player_pos[index].y = new_y;
	}
	kfree(moves);
	return len;
}

unsigned int generate_random_number(unsigned int min_value, unsigned int max_value) {

	unsigned int number = (__get_random_u32_below(max_value) % (max_value - min_value + 1)) + min_value;
	return number;
}

static long maze_dev_ioctl(struct file *fp, unsigned int cmd, unsigned long arg) {
	// printk(KERN_INFO "maze: ioctl cmd=%u arg=%lu.\n", cmd, arg);
	coord_t data;
	memset(&data, 0, sizeof(data));

	int index;
	for (index = 0; index < _MAZE_MAXUSER; ++ index) if (pids[index] == current->pid) break;
	
	switch (cmd) {

		break; case MAZE_CREATE: // Create a new maze with size set by coord_t.
		    if (copy_from_user(&data, (int __user *)arg, sizeof(data))) return -EBUSY;
			if (data.x > _MAZE_MAXX || data.y > _MAZE_MAXY || data.x < 0 || data.y < 0) return -EINVAL;
			
			// check if created already, try to allocate if not.
			if (index < _MAZE_MAXUSER) return -EEXIST;
			for (index = 0; index < _MAZE_MAXUSER; ++index) if (pids[index] == -1) break; // found vacant ?
			if (index == _MAZE_MAXUSER) return -ENOMEM;

			pids[index] = current->pid;
			maze_created[index] = 1;
			maze_size[index] = data;

			unsigned int x_s = (int)generate_random_number(1, maze_size[index].x - 2);
			unsigned int y_s = (int)generate_random_number(1, maze_size[index].y - 2);
			start_pos[index] = (coord_t) {x_s, y_s};
			player_pos[index] = start_pos[index];
			unsigned int x_e = (int)generate_random_number(1, maze_size[index].x - 2);
			unsigned int y_e = (int)generate_random_number(1, maze_size[index].y - 2);
			end_pos[index] = (coord_t) {x_e, y_e};

			for (int i = 0; i < maze_size[index].y; ++i) {
				for (int j = 0; j < maze_size[index].x; ++j) mazes[index][i][j] = 1;
			}
			int c_x = start_pos[index].x;
			int c_y = start_pos[index].y;
			int y_dist = end_pos[index].y - c_y;
			int x_dist = end_pos[index].x - c_x;

			mazes[index][c_y][c_x] = 0;
			int dir;
			dir = (x_dist > 0) ? 1 : -1;
			while (c_x != end_pos[index].x) {
				mazes[index][c_y][c_x] = 0;
				c_x += dir;
			}
			mazes[index][c_y][c_x] = 0;
			
			dir = (y_dist > 0) ? 1 : -1;
			while (c_y != end_pos[index].y) {
				mazes[index][c_y][c_x] = 0;
				c_y += dir;
			} 
			mazes[index][end_pos[index].y][end_pos[index].x] = 0;
			for (int i = 1; i < maze_size[index].y - 1; ++i) {
				unsigned int holes = (int)generate_random_number(1, (int)(((maze_size[index].x - 2) * 2 + 4) / 3));
				unsigned int start = (int)generate_random_number(1, maze_size[index].x - 1 - holes);
				for (int j = 0; j < holes; ++j) mazes[index][i][start + j] = 0;
			}

		break; case MAZE_RESET: // Reset the position of the player to the start position.
			if (index == _MAZE_MAXUSER) return -ENOENT;
			player_pos[index] = start_pos[index];

		break; case MAZE_DESTROY: // Destroy a maze if it has been created.
			if (index == _MAZE_MAXUSER) return -ENOENT;

			maze_created[index] = 0;
			pids[index] = -1;
			maze_size[index] = (coord_t) {-1, -1};
			start_pos[index] = (coord_t) {-1, -1};
			end_pos[index] = (coord_t) {-1, -1};
			player_pos[index] = (coord_t) {-1, -1};

		break; case MAZE_GETSIZE: // Get the dimension of the maze.
			if (index == _MAZE_MAXUSER) return -ENOENT;
			if (copy_to_user((coord_t __user *)arg, &maze_size[index], sizeof(coord_t))) return -EBUSY;

		break; case MAZE_MOVE: // The valid values only include (-1, 0), (1, 0), (0, -1), and (0, 1).
			if (index == _MAZE_MAXUSER) return -ENOENT;
			if (copy_from_user(&data, (coord_t __user *)arg, sizeof(data))) return -EBUSY;

			int new_x = player_pos[index].x + data.x;
			int new_y = player_pos[index].y + data.y;
			if (new_x <= 0 || new_x >= maze_size[index].x - 1 \
			|| new_y <= 0 || new_y >= maze_size[index].y - 1  \
			|| mazes[index][new_y][new_x] == 1) return 0;

			player_pos[index].x = new_x;
			player_pos[index].y = new_y;

		break; case MAZE_GETPOS: // Get the player’s position on the maze.
			if (index == _MAZE_MAXUSER) return -ENOENT;		
			if (copy_to_user((coord_t __user *)arg, &player_pos[index], sizeof(coord_t))) return -EBUSY;

		break; case MAZE_GETSTART:
			if (index == _MAZE_MAXUSER) return -ENOENT;		
			if (copy_to_user((coord_t __user *)arg, &start_pos[index], sizeof(coord_t))) return -EBUSY;
			
		break; case MAZE_GETEND:
			if (index == _MAZE_MAXUSER) return -ENOENT;
			if (copy_to_user((coord_t __user *)arg, &end_pos[index], sizeof(coord_t))) return -EBUSY;
	}
	return 0;
}

static int maze_dev_close(struct inode *i, struct file *f) {

	int index;
	for (index = 0; index < _MAZE_MAXUSER; ++index) if (pids[index] == current->pid) break;
	if (index < _MAZE_MAXUSER) {
		maze_created[index] = 0;
		pids[index] = -1;
		maze_size[index] = (coord_t) {-1, -1};
		start_pos[index] = (coord_t) {-1, -1};
		end_pos[index] = (coord_t) {-1, -1};
		player_pos[index] = (coord_t) {-1, -1};
	}
	printk(KERN_INFO "maze: device closed.\n");
	return 0;
}

// what's this?
static char *maze_devnode(const struct device *dev, umode_t *mode) {
	
	if (mode == NULL) return NULL;
	*mode = 0666;
	return NULL;
}

static const struct file_operations maze_dev_fops = {
	.owner = THIS_MODULE,
	.open = maze_dev_open,
	.read = maze_dev_read,
	.write = maze_dev_write,
	.unlocked_ioctl = maze_dev_ioctl,
	.release = maze_dev_close
};

static int maze_proc_read(struct seq_file *m, void *v) { //  show the status of all the mazes created by user space processes.

	for (int k = 0; k < _MAZE_MAXUSER; ++k) {
		seq_printf(m, "#%02d: ", k);
		if (maze_created[k] == 0) {
			seq_printf(m, "vacancy\n\n");
			continue;
		}
		seq_printf(m, "pid %d - [%d x %d]: (%d, %d) -> (%d, %d) @ (%d, %d)\n", \
					pids[k], maze_size[k].x, maze_size[k].y, start_pos[k].x, start_pos[k].y,
					end_pos[k].x, end_pos[k].y, player_pos[k].x, player_pos[k].y);
		// printk("player_pos[k].x = %d", player_pos[k].x);
		for (int i = 0; i < maze_size[k].y; ++i) {
			seq_printf(m, "- %03d: ", i);
			for (int j = 0; j < maze_size[k].x; ++j) {
				if (player_pos[k].x == j && player_pos[k].y == i) seq_printf(m, "*");
				else if (start_pos[k].x == j && start_pos[k].y == i) seq_printf(m, "S");
				else if (end_pos[k].x == j && end_pos[k].y == i) seq_printf(m, "E");
				else if (mazes[k][i][j] == 1) seq_printf(m, "#");
				else seq_printf(m, ".");
			}
			seq_printf(m, "\n");
		}
		seq_printf(m, "\n");
	}
	return 0;
}

static int maze_proc_open(struct inode *inode, struct file *file) {
	
	return single_open(file, maze_proc_read, NULL);
}

static const struct proc_ops maze_proc_fops = {
	.proc_open = maze_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static int __init maze_init(void) {
	
	// create /dev
    alloc_chrdev_region(&devnum, 0, MAZE_DEV_CNT, "maze");
	cdev_init(&m_cdev, &maze_dev_fops);
	cdev_add(&m_cdev, devnum, MAZE_DEV_CNT);
	
	m_class = class_create("maze class");
    m_class->devnode = maze_devnode;
	device_create(m_class, NULL, devnum, NULL, "maze");

	// create /proc
    proc_create("maze", 0, NULL, &maze_proc_fops);
	printk(KERN_INFO "maze: initialized.\n");
	return 0; // Non-zero return means that the module couldn't be loaded.
}

static void __exit maze_cleanup(void) {

	// remove /proc
	remove_proc_entry("maze", NULL);

	// remove /dev
	cdev_del(&m_cdev);
	device_destroy(m_class, devnum);	
	class_destroy(m_class);
	unregister_chrdev_region(devnum, 1);

	printk(KERN_INFO "maze: cleaned up.\n");
}

module_init(maze_init);
module_exit(maze_cleanup);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jasminechennnnn");
MODULE_DESCRIPTION("The unix programming course Lab02.");