#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>

static int major;


DECLARE_WAIT_QUEUE_HEAD(module_queue);


struct cycle_buffer
{
	char *buffer;
	size_t buf_size;
	ssize_t reader_ptr;
	ssize_t writer_ptr;
	ssize_t free_bytes;
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
		if (buffer->free_bytes == buffer->buf_size)
		{
			wake_up(&module_queue);
			wait_event_interruptible(module_queue, buffer->free_bytes < buffer->buf_size);
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
		if (buffer->free_bytes == 0)
		{
			wake_up(&module_queue);
			wait_event_interruptible(module_queue, buffer->free_bytes > 0);
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
