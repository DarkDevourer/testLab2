#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/wait.h>
#include <linux/mutex.h>
#include <linux/types.h>

#include <uapi/asm-generic/ioctl.h>

#include "module_pipe.h"

static int major;

struct cycle_buffer
{
	char *buffer;
	size_t buf_size;
	ssize_t reader_ptr;
	ssize_t writer_ptr;
	ssize_t free_bytes;
	wait_queue_head_t module_queue;
	struct mutex lock;
};

static struct cycle_buffer *buffer;

static struct cycle_buffer *allocate_buffer (ssize_t begin_size)
{
	struct cycle_buffer *buffer;

	buffer = kmalloc(sizeof(struct cycle_buffer), GFP_KERNEL);
	if (buffer == NULL)
	{
		return NULL;
	}

	buffer->buf_size = begin_size;
	buffer->buffer = kmalloc(begin_size, GFP_KERNEL);
	if (buffer->buffer == NULL)
	{
		kfree(buffer);
		return NULL;
	}

	buffer->reader_ptr = 0;
	buffer->writer_ptr = 0;
	buffer->free_bytes = begin_size;
	init_waitqueue_head(&buffer->module_queue);
	mutex_init(&buffer->lock);
	return buffer;
}

static void free_buffer(struct cycle_buffer *buffer)
{
	kfree(buffer->buffer);
	kfree(buffer);
}


static ssize_t lab2_read(struct file *file, char __user *buf,
			 size_t count, loff_t *pos)
{
	char *tmp_buffer;
	tmp_buffer = kmalloc(count, GFP_KERNEL);
	int read_left = count; //Cколько осталось считать байт

	while (read_left > 0)
	{
		mutex_lock(&buffer->lock);
		if (buffer->free_bytes == buffer->buf_size)
		{
			wake_up(&buffer->module_queue);
			mutex_unlock(&buffer->lock);
			wait_event_interruptible(buffer->module_queue, buffer->free_bytes < buffer->buf_size);
			mutex_lock(&buffer->lock);
		}

		int read_can; //Сколько мы можем считать байт в данной итерации цикла

		if (buffer->reader_ptr >= buffer->writer_ptr)
		{
			read_can = buffer->buf_size + buffer->writer_ptr - buffer->reader_ptr;
		}
		else
		{
			read_can = buffer->writer_ptr - buffer->reader_ptr;
		}
		if (read_can > read_left)
		{
			read_can = read_left;
		}

		if (buffer->reader_ptr + read_can > buffer->buf_size-1) //Если при считывании выходим за границы буфера
		{
			memcpy(tmp_buffer+(count-read_left), buffer->buffer+buffer->reader_ptr, buffer->buf_size-buffer->reader_ptr); //Считываем сколько можем до конца буффера

			read_left -= buffer->buf_size-buffer->reader_ptr;
			read_can -= buffer->buf_size-buffer->reader_ptr;
			buffer->free_bytes += buffer->buf_size-buffer->reader_ptr;
			buffer->reader_ptr = 0;
		}

		memcpy(tmp_buffer+(count-read_left), buffer->buffer+buffer->reader_ptr, read_can);
		read_left -= read_can;
		buffer->free_bytes += read_can;
		buffer->reader_ptr += read_can;
		read_can = 0;
		printk("%s\n",tmp_buffer);
		printk("%d\n",buffer->reader_ptr);
		printk("%d\n",buffer->free_bytes);
		mutex_unlock(&buffer->lock);
	}

	wake_up(&buffer->module_queue);

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
		mutex_lock(&buffer->lock);
		if (buffer->free_bytes == 0)
		{
			wake_up(&buffer->module_queue);
			mutex_unlock(&buffer->lock);
			wait_event_interruptible(buffer->module_queue, buffer->free_bytes > 0);
			mutex_lock(&buffer->lock);
		}

		int write_bytes = write_left;
		if (write_left > buffer->free_bytes)
		{
			write_bytes = buffer->free_bytes;
		}

		printk("%d\n", write_bytes);

		if (buffer->writer_ptr+write_bytes>buffer->buf_size-1)
		{
			int ov_size = buffer->buf_size - buffer->writer_ptr; //Сколько байт можно записать до конца буфера
			memcpy(buffer->buffer+buffer->writer_ptr, tmp_buffer+(count-write_left), ov_size);
			buffer->writer_ptr = 0;
			write_bytes -= ov_size;
			write_left -= ov_size;
			buffer->free_bytes -= ov_size;
		}

		memcpy(buffer->buffer+buffer->writer_ptr, tmp_buffer+(count-write_left), write_bytes);

		buffer->free_bytes -= write_bytes;
		write_left -= write_bytes;
		buffer->writer_ptr += write_bytes; 
		printk("%d\n",buffer->free_bytes);
		printk("%s\n",buffer->buffer);
		write_bytes = 0;
		mutex_unlock(&buffer->lock);
	}

	wake_up(&buffer->module_queue);

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

static long lab2_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	struct cycle_buffer *temp;
	int res;

	pr_alert("my_pipe ioctl; cmd is %d, arg is %lu\n", cmd, arg);

	switch (cmd) {
	case BUF_CAPACITY:
		pr_alert("cmd is BUF_CAPACITY\n");

		if (buffer == NULL) {
			pr_err("Could not allocate requested circular buffer in ioctl\n");
			return -EINVAL;
		}

		res = mutex_lock_interruptible(&buffer->lock);
		if (res != 0) {
			pr_err("Mutex interrupted with return value %d\n", res);
			return -EINVAL;
		}

		if (buffer->free_bytes < buffer->buf_size) {
			pr_alert("Circular buffer is not empty, could not change capacity");
			mutex_unlock(&buffer->lock);
			return -EINVAL;
		}

		temp = allocate_buffer(arg);

		free_buffer(buffer);
		buffer = temp;
		pr_alert("Buffer capacity changed to %lu\n", arg);
		mutex_unlock(&buffer->lock);
		return 0;

	default:
		pr_alert("cmd is unknown\n");
		return -ENOTTY;
	}
}

static struct file_operations fops = {
	.read	= lab2_read,
	.write	= lab2_write,
	.open   = lab2_open,
	.release  = lab2_release,
	.unlocked_ioctl = lab2_ioctl,
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

	buffer = allocate_buffer(100);

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
