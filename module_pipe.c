#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>

static int major;

static char buffer[100];
static buf_size = 100;
static int reader_ptr = 0;
static int writer_ptr = 0;
static int free_bytes = 100;

/*
struct cycle_buffer
{
	static char buffer[100];
	static buf_size = 100;
	static int reader_ptr = 0;
	static int writer_ptr = 0;
	static int free_bytes = 100;
};
*/

static ssize_t lab2_read(struct file *file, char __user *buf,
			 size_t count, loff_t *pos)
{
	char *tmp_buffer;
	tmp_buffer = kmalloc(count, GFP_KERNEL);

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

	int i;
	for(i = 0; i<count;i++)
	{

		buffer[writer_ptr] = tmp_buffer[i];
		writer_ptr++;

		if (writer_ptr == 100)
		{
			writer_ptr = 0;
		}
	}

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
