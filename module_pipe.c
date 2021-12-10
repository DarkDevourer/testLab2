// SPDX-License-Identifier: GPL-2.0

#include <linux/init.h>
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

DEFINE_MUTEX(global_mutex);

static int major;

const size_t BUF_SIZE = 20;

static int gid_cmp(const void *_a, const void *_b)
{
	kgid_t a = *(kgid_t *)_a;
	kgid_t b = *(kgid_t *)_b;

	return gid_gt(a, b) - gid_lt(a, b);
}

struct cycle_buffer {
	char *buffer;
	size_t buf_size;
	ssize_t reader_ptr;
	ssize_t writer_ptr;
	ssize_t free_bytes;
	wait_queue_head_t module_queue;
	struct mutex lock;
};

struct buff_array {
	size_t n;
	struct cycle_buffer **buf_arr;
	kgid_t *gid_arr;
};

static struct buff_array *buffers;

static struct cycle_buffer *allocate_buffer(ssize_t begin_size)
{
	struct cycle_buffer *buffer;

	buffer = kmalloc(sizeof(struct cycle_buffer), GFP_KERNEL);
	if (buffer == NULL)
		return NULL;

	buffer->buf_size = begin_size;
	buffer->buffer = kmalloc(begin_size, GFP_KERNEL);
	if (buffer->buffer == NULL) {
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

static struct buff_array *allocate_buff_array(void)
{
	struct buff_array *arr;

	mutex_lock_interruptible(&global_mutex);

	arr = kmalloc(sizeof(struct buff_array), GFP_KERNEL);
	if (arr == NULL) {
		mutex_unlock(&global_mutex);
		return NULL;
	}

	arr->n = 0;
	arr->buf_arr = NULL;
	arr->gid_arr = NULL;
	mutex_unlock(&global_mutex);
	return arr;
}

static void free_buff_array(void)
{
	int i;

	mutex_lock_interruptible(&global_mutex);
	for (i = 0; i < buffers->n; i++)
		free_buffer(buffers->buf_arr[i]);

	kfree(buffers->buf_arr);
	kfree(buffers->gid_arr);
	kfree(buffers);
	mutex_unlock(&global_mutex);
}

static struct cycle_buffer *add_buffer(kgid_t gid)
{
	struct cycle_buffer **tmp_buf_arr;
	kgid_t *tmp_gid_arr;

	mutex_lock_interruptible(&global_mutex);
	size_t nsize = ((buffers->n) + 1);

	tmp_buf_arr = krealloc(buffers->buf_arr, nsize * sizeof(struct cycle_buffer *), GFP_KERNEL);
	if (tmp_buf_arr == NULL) {
		mutex_unlock(&global_mutex);
		pr_err("Could not reallocate memory for assoc_arr_gid_buf_t->buf_arr\n");
		return NULL;
	}

	tmp_gid_arr = krealloc(buffers->gid_arr, nsize * sizeof(kgid_t), GFP_KERNEL);
	if (tmp_gid_arr == NULL) {
		mutex_unlock(&global_mutex);
		pr_err("Could not reallocate memory for assoc_arr_gid_buf_t->tmp_gid_arr\n");
		return NULL;
	}

	tmp_gid_arr[nsize - 1] = gid;
	tmp_buf_arr[nsize - 1] = allocate_buffer(BUF_SIZE);

	buffers->buf_arr = tmp_buf_arr;
	buffers->gid_arr = tmp_gid_arr;
	buffers->n++;
	mutex_unlock(&global_mutex);
	return buffers->buf_arr[nsize-1];
}

static struct cycle_buffer *find_buffer(kgid_t gid)
{
	int i;

	for (i = 0; i < buffers->n; i++) {
		if (gid_cmp((void *)&gid, (void *)&buffers->gid_arr[i]) == 0) {
			pr_alert("Found matching kgid! At index %d\n", i);
			return buffers->buf_arr[i];
		}
	}
	return NULL;
}

static ssize_t lab2_read(struct file *file, char __user *buf,
			 size_t count, loff_t *pos)
{
	struct cycle_buffer *buffer = file->private_data;

	char *tmp_buffer;

	tmp_buffer = kmalloc(count, GFP_KERNEL);
	int read_left = count; //Cколько осталось считать байт

	if (tmp_buffer == NULL)
		return 0;

	while (read_left > 0) {
		mutex_lock_interruptible(&buffer->lock);
		if (buffer->free_bytes == buffer->buf_size) {
			wake_up(&buffer->module_queue);
			mutex_unlock(&buffer->lock);
			wait_event_interruptible(buffer->module_queue, buffer->free_bytes < buffer->buf_size);
			mutex_lock_interruptible(&buffer->lock);
		}

		int read_can; //Сколько мы можем считать байт в данной итерации цикла

		if (buffer->reader_ptr >= buffer->writer_ptr)
			read_can = buffer->buf_size + buffer->writer_ptr - buffer->reader_ptr;
		else
			read_can = buffer->writer_ptr - buffer->reader_ptr;

		if (read_can > read_left)
			read_can = read_left;

		if (buffer->reader_ptr + read_can > buffer->buf_size-1) {
			memcpy(tmp_buffer+(count-read_left), buffer->buffer+buffer->reader_ptr, buffer->buf_size-buffer->reader_ptr); //Считываем сколько можем до конца буффера

			read_left -= buffer->buf_size-buffer->reader_ptr;
			read_can -= buffer->buf_size-buffer->reader_ptr;
			buffer->free_bytes += buffer->buf_size-buffer->reader_ptr;
			buffer->reader_ptr = 0;
		}

		memcpy(tmp_buffer+(count-read_left), buffer->buffer+buffer->reader_ptr, read_can);
		buffer->free_bytes += read_can;
		buffer->reader_ptr += read_can;
		pr_alert("%d\n", buffer->free_bytes);
		mutex_unlock(&buffer->lock);
		read_left -= read_can;
		read_can = 0;
		pr_alert("%s\n", tmp_buffer);
		pr_alert("%d\n", buffer->reader_ptr);
	}

	wake_up(&buffer->module_queue);

	copy_to_user(buf, tmp_buffer, count);
	kfree(tmp_buffer);
	return count;
}

static ssize_t lab2_write(struct file *file, const char __user *buf,
			 size_t count, loff_t *pos)
{
	struct cycle_buffer *buffer = file->private_data;
	char *tmp_buffer;

	tmp_buffer = kmalloc(count, GFP_KERNEL);

	if (tmp_buffer == NULL)
		return 0;

	copy_from_user(tmp_buffer, buf, count);
	pr_alert("%s\n", tmp_buffer);
	int write_left = count;

	while (write_left > 0) {
		mutex_lock_interruptible(&buffer->lock);
		if (buffer->free_bytes == 0) {
			wake_up(&buffer->module_queue);
			mutex_unlock(&buffer->lock);
			wait_event_interruptible(buffer->module_queue, buffer->free_bytes > 0);
			mutex_lock_interruptible(&buffer->lock);
		}

		int write_bytes = write_left;

		if (write_left > buffer->free_bytes)
			write_bytes = buffer->free_bytes;

		pr_alert("%d\n", write_bytes);

		if (buffer->writer_ptr+write_bytes > buffer->buf_size-1) {
			int ov_size = buffer->buf_size - buffer->writer_ptr; //Сколько байт можно записать до конца буфера

			memcpy(buffer->buffer+buffer->writer_ptr, tmp_buffer+(count-write_left), ov_size);
			buffer->writer_ptr = 0;
			write_bytes -= ov_size;
			write_left -= ov_size;
			buffer->free_bytes -= ov_size;
		}

		memcpy(buffer->buffer+buffer->writer_ptr, tmp_buffer+(count-write_left), write_bytes);
		buffer->free_bytes -= write_bytes;
		buffer->writer_ptr += write_bytes;
		mutex_unlock(&buffer->lock);
		write_left -= write_bytes;
		pr_alert("%d\n", buffer->free_bytes);
		pr_alert("%s\n", buffer->buffer);
		write_bytes = 0;
	}

	wake_up(&buffer->module_queue);

	kfree(tmp_buffer);
	return count;
}

static int lab2_open(struct inode *i, struct file *file)
{
	file->private_data = find_buffer(file->f_cred->egid);

	if (file->private_data == NULL)
		file->private_data = add_buffer(file->f_cred->egid);

	if (file->private_data == NULL)
		return -1;

	pr_alert("Just open\n");
	return 0;
}

static int lab2_release(struct inode *i, struct file *f)
{
	pr_alert("Just close\n");
	return 0;
}

static long lab2_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct cycle_buffer *temp;
	int res, i;

	pr_alert("my_pipe ioctl; cmd is %d, arg is %lu\n", cmd, arg);

	struct cycle_buffer *buffer = file->private_data;

	switch (cmd) {
	case BUF_CAPACITY:
		pr_alert("cmd is BUF_CAPACITY\n");

		if (buffer == NULL) {
			pr_err("Could not allocate requested circular buffer in ioctl\n");
			return -EINVAL;
		}

		res = mutex_lock_interruptible(&buffer->lock);

		if (buffer->free_bytes < buffer->buf_size) {
			mutex_unlock(&buffer->lock);
			pr_alert("Circular buffer is not empty, could not change capacity");
			return -EINVAL;
		}

		temp = allocate_buffer(arg);

		if (temp == NULL) {
			mutex_unlock(&buffer->lock);
			return -ENOTTY;
		}

		for (i = 0; i < buffers->n; i++)
			if (buffers->buf_arr[i] == buffer) {
				buffers->buf_arr[i] = temp;
				free_buffer(buffer);
			}

		mutex_unlock(&buffer->lock);
		pr_alert("Buffer capacity changed to %lu\n", arg);
		return 0;

	default:
		pr_alert("cmd is unknown\n");
		return -ENOTTY;
	}
}

static const struct file_operations fops = {
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
		pr_alert("failed to register_chrdev failed with %d\n", major);
		/* should follow 0/-E convention ... */
		return major;
	}

	buffers = allocate_buff_array();
	if (buffers == NULL)
		return -1;

	pr_alert("/dev/lab2_device assigned major %d\n", major);
	return 0;
}

static void __exit mod_exit(void)
{
	free_buff_array();
	unregister_chrdev(major, "lab2_device");
	pr_alert("Exited\n");
}

module_init(mod_init);
module_exit(mod_exit);

MODULE_AUTHOR("Nazarchuk G");
MODULE_DESCRIPTION("Test Pipe Driver");
MODULE_LICENSE("GPL");