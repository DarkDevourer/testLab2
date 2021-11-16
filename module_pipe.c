#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>

static int major;

static char buffer[10];
static int buf_size = 10;
static int reader_ptr = 0;
static int writer_ptr = 0;
static int free_bytes = 10;

DECLARE_WAIT_QUEUE_HEAD(module_queue);

/*
struct cycle_buffer
{
	static char buffer[10];
	static buf_size = 10;
	static int reader_ptr = 0;
	static int writer_ptr = 0;
	static int free_bytes = 10;
};
*/

static ssize_t lab2_read(struct file *file, char __user *buf,
			 size_t count, loff_t *pos)
{
	char *tmp_buffer;
	tmp_buffer = kmalloc(count, GFP_KERNEL);
	int read_left = count; //Cколько осталось считать байт

	while (read_left > 0)
	{
		if (free_bytes == buf_size)
		{
			wake_up(&module_queue);
			wait_event_interruptible(module_queue, free_bytes != 0);
		}

		int read_can; //Сколько мы можем считать байт в данной итерации цикла

		if (reader_ptr > writer_ptr)
		{
			read_can = 10 + writer_ptr - reader_ptr;
		}
		else
		{
			read_can = writer_ptr - reader_ptr;
		}

		if (read_can > read_left)
		{
			read_can = read_left;
		}

		if (read_can + reader_ptr > buf_size) //Если при считывании выходим за границы буфера
		{
			memcpy(tmp_buffer+reader_ptr, buffer+(count-read_left), buf_size-reader_ptr-1); //Считываем сколько можем до конца буффера
			printk("%d\n",buf_size-reader_ptr-1);

			read_left -= buf_size-reader_ptr+1;
			read_can -= buf_size-reader_ptr+1;
			free_bytes += buf_size-reader_ptr+1;
			reader_ptr = 0;
		}

		memcpy(tmp_buffer+reader_ptr, buffer+(count-read_left), read_can);
		printk("%d\n",read_can);
		read_left -= read_can;
		free_bytes += read_can;
		reader_ptr += read_can;
		read_can = 0;
		
	}

	wake_up(&module_queue);

	copy_to_user(buf, tmp_buffer, count);
	kfree(tmp_buffer);
	return count;
}

static ssize_t lab2_write(struct file *file, const char __user *buf,
			 size_t count, loff_t *pos)
{
	
	char *tmp_buffer;
	tmp_buffer = kmalloc(count, GFP_KERNEL);
	copy_from_user(tmp_buffer, buf, count);
	pr_alert("%s\n", tmp_buffer);
	int write_left = count;

	while (write_left > 0)
	{
		if (free_bytes == 0)
		{
			wake_up(&module_queue);
			wait_event_interruptible(module_queue, free_bytes > 0);
		}

		int write_bytes = write_left;
		if (write_left > free_bytes)
		{
			write_bytes = free_bytes;
		}

		if (writer_ptr+write_bytes>buf_size-1)
		{
			int ov_size = buf_size - writer_ptr - 1;
			memcpy(buffer+writer_ptr, tmp_buffer, ov_size);
			writer_ptr = 0;
			write_bytes -= ov_size;
			write_left -= ov_size;
			free_bytes -= ov_size;
		}

		memcpy(buffer+writer_ptr, tmp_buffer+(count-write_left), write_bytes);

		free_bytes -= write_bytes;
		write_left -= write_bytes;
		writer_ptr += write_bytes;
		write_bytes = 0;
	}

	wake_up(&module_queue);

	kfree(tmp_buffer);
	return count;
}

static int lab2_open(struct inode *i, struct file *f)
{
	printk("Just open\n");
	return 0;
}

static int lab2_release(struct inode *i, struct file *f)
{
	printk("Just close\n");
	return 0;
}

static struct file_operations fops = {
	.read	= lab2_read,
	.write	= lab2_write,
	.open   = lab2_open,
	.release  = lab2_release,
};

static int __init mod_init(void)
{
	/* 0 is ? */
	major = register_chrdev(0, "lab2_device", &fops);
	if (major < 0) {
		printk("failed to register_chrdev failed with %d\n", major);
		/* should follow 0/-E convention ... */
		return major;
	}
	printk("/dev/lab2_device assigned major %d\n", major);
	return 0;
}

static void __exit mod_exit(void)
{
	unregister_chrdev(major, "lab2_device");
	printk("Exited\n");
}

module_init(mod_init);
module_exit(mod_exit);

MODULE_AUTHOR("Nazarchuk G");
MODULE_DESCRIPTION("Test Pipe Driver");
MODULE_LICENSE("GPL");
