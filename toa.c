#include "toa.h"

#include <linux/ktime.h>
#include <linux/spinlock.h>
#include <linux/time64.h>
#include <linux/timekeeping.h>
#include <linux/sort.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/proc_fs.h>
#include <linux/time.h>
#include <linux/mm.h>
#include <linux/seq_file.h>
#include <linux/version.h>
#include <net/inet_sock.h>
#include <net/inet_connection_sock.h>

#if defined(CONFIG_X86)
#include <asm/pgtable.h>
#endif

/* ============================================================
 *  MODULE PARAMETERS
 * ============================================================
 */

/* 每 CPU FIFO 大小，默认 4096，可通过模块参数调整 */
static int toa_detail_fifo_size = 4096;
module_param(toa_detail_fifo_size, int, 0644);
MODULE_PARM_DESC(toa_detail_fifo_size,
                 "Per-CPU TOA detail FIFO size");

/*
 * 全局最大条数：
 *   - <=0 时自动按 toa_detail_fifo_size * num_possible_cpus() 计算
 *   - >0 时使用用户指定值
 */
static int toa_detail_total_max = 0;
module_param(toa_detail_total_max, int, 0644);
MODULE_PARM_DESC(toa_detail_total_max,
                 "Global max TOA detail entries (<=0 for auto: fifo_size * nr_cpus)");

/* ============================================================
 *  PROC OPS 兼容
 * ============================================================
 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
#define TOA_PROC_OPS struct proc_ops
#define TOA_PROC_OPEN     .proc_open
#define TOA_PROC_READ     .proc_read
#define TOA_PROC_LSEEK    .proc_lseek
#define TOA_PROC_RELEASE  .proc_release
#else
#define TOA_PROC_OPS struct file_operations
#define TOA_PROC_OPEN     .open
#define TOA_PROC_READ     .read
#define TOA_PROC_LSEEK    .llseek
#define TOA_PROC_RELEASE  .release
#endif

/* ============================================================
 *  kvmalloc/kvfree 兼容
 * ============================================================
 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,12,0)
static inline void *kvmalloc(size_t size, gfp_t flags)
{
    void *ret = kmalloc(size, flags);
    return ret ? ret : vmalloc(size);
}

static inline void kvfree(const void *addr)
{
    if (is_vmalloc_addr(addr))
        vfree(addr);
    else
        kfree(addr);
}
#endif

/* ============================================================
 *  TOA DETAIL FIFO（每 CPU）
 * ============================================================
 */

struct toa_detail_entry {
    __be32 src_ip;
    __be16 src_port;
    struct timespec64 timestamp;
    __be32 dst_ip;
    __be16 dst_port;
    __be32 toa_ip;
    __be16 toa_port;
};

struct toa_detail_fifo {
    struct toa_detail_entry *entries;
    int size;
    int head;
    int tail;
    int count;
    spinlock_t lock;
};

static struct toa_detail_fifo __percpu *toa_detail_fifos;
static atomic_t total_count_global = ATOMIC_INIT(0);

/* ============================================================
 *  STAT MIB（定义在 toa.h）
 * ============================================================
 */

static struct toa_stat_mib __percpu *ext_stats;

/* ============================================================
 *  每 socket 的 TOA 私有数据（修复版）
 * ============================================================
 */

struct toa_sock_info {
    struct toa_data tdata;                 /* 解析出的 TOA 数据 */
    void (*orig_destruct)(struct sock *);  /* 原始 sk_destruct */
};

/* ============================================================
 *  FIFO INIT / DESTROY（使用 vzalloc）
 * ============================================================
 */

static int toa_detail_fifo_init_all(void)
{
    int cpu;

    toa_detail_fifos = alloc_percpu(struct toa_detail_fifo);
    if (!toa_detail_fifos)
        return -ENOMEM;

    for_each_possible_cpu(cpu) {
        struct toa_detail_fifo *fifo = per_cpu_ptr(toa_detail_fifos, cpu);

        fifo->size  = toa_detail_fifo_size;
        fifo->head  = 0;
        fifo->tail  = 0;
        fifo->count = 0;
        spin_lock_init(&fifo->lock);

        fifo->entries = vzalloc(sizeof(struct toa_detail_entry) * fifo->size);
        if (!fifo->entries)
            return -ENOMEM;
    }

    return 0;
}

static void toa_detail_fifo_destroy_all(void)
{
    int cpu;

    if (!toa_detail_fifos)
        return;

    for_each_possible_cpu(cpu) {
        struct toa_detail_fifo *fifo = per_cpu_ptr(toa_detail_fifos, cpu);
        if (fifo->entries) {
            vfree(fifo->entries);
            fifo->entries = NULL;
        }
    }

    free_percpu(toa_detail_fifos);
    toa_detail_fifos = NULL;
}

/* ============================================================
 *  FIFO ADD
 * ============================================================
 */

static void toa_detail_fifo_add(__be32 src_ip, __be16 src_port,
                                struct timespec64 timestamp,
                                __be32 dst_ip, __be16 dst_port,
                                __be32 toa_ip, __be16 toa_port)
{
    struct toa_detail_fifo *fifo = this_cpu_ptr(toa_detail_fifos);
    struct toa_detail_entry *entry;
    unsigned long flags;
    int total_count;

    total_count = atomic_read(&total_count_global);

    spin_lock_irqsave(&fifo->lock, flags);

    /* 全局限制：当 total_count >= toa_detail_total_max 时覆盖旧记录 */
    if (total_count >= toa_detail_total_max && fifo->count > 0) {
        fifo->head = (fifo->head + 1) % fifo->size;
        fifo->count--;
        atomic_dec(&total_count_global);
    }

    if (fifo->count < fifo->size) {
        entry = &fifo->entries[fifo->tail];
        fifo->tail = (fifo->tail + 1) % fifo->size;
        fifo->count++;
        atomic_inc(&total_count_global);
    } else {
        /* 本 CPU FIFO 满，覆盖最旧的一条 */
        entry = &fifo->entries[fifo->head];
        fifo->head = (fifo->head + 1) % fifo->size;
    }

    entry->src_ip    = src_ip;
    entry->src_port  = src_port;
    entry->timestamp = timestamp;
    entry->dst_ip    = dst_ip;
    entry->dst_port  = dst_port;
    entry->toa_ip    = toa_ip;
    entry->toa_port  = toa_port;

    spin_unlock_irqrestore(&fifo->lock, flags);
}

/* ============================================================
 *  TOA CORE：解析 TCP 选项（修复版：不分配内存）
 * ============================================================
 */

/*
 * 修复点：
 *   - 不再分配 struct toa_data，只通过 out 参数返回
 *   - 仍然向 detail FIFO 记录一份日志
 */
static bool get_toa_data(struct sk_buff *skb, __be32 src_ip, __be16 src_port,
                         __be32 dst_ip, __be16 dst_port,
                         struct toa_data *out)
{
    struct tcphdr *th;
    int length;
    unsigned char *ptr;
    unsigned char buff[(15 * 4) - sizeof(struct tcphdr)];
    struct timespec64 timestamp;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0)
    ktime_get_real_ts64(&timestamp);
#else
    getnstimeofday64(&timestamp);
#endif

    if (!skb || !out)
        return false;

    th = tcp_hdr(skb);
    length = (th->doff * 4) - sizeof(struct tcphdr);
    ptr = skb_header_pointer(skb, sizeof(struct tcphdr), length, buff);
    if (!ptr)
        return false;

    while (length > 0) {
        int opcode = *ptr++;
        int opsize;

        switch (opcode) {
        case TCPOPT_EOL:
            return false;
        case TCPOPT_NOP:
            length--;
            continue;
        default:
            opsize = *ptr++;
            if (opsize < 2)
                return false;
            if (opsize > length)
                return false;
            if (opcode == TCPOPT_TOA && opsize == TCPOLEN_TOA) {
                /* 直接把 TCP 选项复制到 out */
                memcpy(out, ptr - 2, sizeof(*out));

                /* 记录详细 TOA 日志 */
                toa_detail_fifo_add(src_ip, src_port, timestamp,
                                    dst_ip, dst_port,
                                    out->ip, out->port);
                return true;
            }
            ptr    += opsize - 2;
            length -= opsize;
        }
    }

    return false;
}

/* ============================================================
 *  sk_destruct 包装，用于释放 TOA 私有数据
 * ============================================================
 */

static void toa_sock_destruct(struct sock *sk)
{
    struct inet_connection_sock *icsk;
    struct toa_sock_info *info;
    void (*orig)(struct sock *sk) = NULL;

    if (!sk)
        return;

    icsk = inet_csk(sk);
    if (icsk) {
        info = (struct toa_sock_info *)icsk->icsk_ulp_data;
        if (info) {
            orig = info->orig_destruct;
            icsk->icsk_ulp_data = NULL;
            kfree(info);
        }
    }

    if (orig)
        orig(sk);
    else if (sk->sk_prot && sk->sk_prot->destroy)
        sk->sk_prot->destroy(sk);
}

/* ============================================================
 *  getname hook（IPv4 / IPv6）
 * ============================================================
 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
static int inet_getname_toa(struct socket *sock, struct sockaddr *uaddr,
                            int peer)
#else
static int inet_getname_toa(struct socket *sock, struct sockaddr *uaddr,
                            int *uaddr_len, int peer)
#endif
{
    int retval;
    struct sock *sk = sock->sk;
    struct sockaddr_in *sin = (struct sockaddr_in *)uaddr;
    struct inet_connection_sock *icsk;
    struct toa_sock_info *info = NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
    retval = inet_getname(sock, uaddr, peer);
#else
    retval = inet_getname(sock, uaddr, uaddr_len, peer);
#endif

    /* 修复版：
     *   - 不再依赖 sk_user_data
     *   - 只读 icsk->icsk_ulp_data 中保存的 TOA 数据
     */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
    if (retval > 0 && peer && sk)
#else
    if (retval == 0 && peer && sk)
#endif
    {
        icsk = inet_csk(sk);
        if (icsk)
            info = (struct toa_sock_info *)icsk->icsk_ulp_data;

        if (info &&
            info->tdata.opcode == TCPOPT_TOA &&
            info->tdata.opsize == TCPOLEN_TOA) {
            TOA_INC_STATS(ext_stats, GETNAME_TOA_OK_CNT);
            sin->sin_port        = info->tdata.port;
            sin->sin_addr.s_addr = info->tdata.ip;
        } else if (info) {
            TOA_INC_STATS(ext_stats, GETNAME_TOA_MISMATCH_CNT);
        } else {
            TOA_INC_STATS(ext_stats, GETNAME_TOA_EMPTY_CNT);
        }
    } else {
        TOA_INC_STATS(ext_stats, GETNAME_TOA_BYPASS_CNT);
    }

    return retval;
}

#ifdef CONFIG_IP_VS_TOA_IPV6
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
static int inet6_getname_toa(struct socket *sock, struct sockaddr *uaddr,
                             int peer)
#else
static int inet6_getname_toa(struct socket *sock, struct sockaddr *uaddr,
                             int *uaddr_len, int peer)
#endif
{
    int retval;
    struct sock *sk = sock->sk;
    struct sockaddr_in6 *sin = (struct sockaddr_in6 *)uaddr;
    struct inet_connection_sock *icsk;
    struct toa_sock_info *info = NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
    retval = inet6_getname(sock, uaddr, peer);
#else
    retval = inet6_getname(sock, uaddr, uaddr_len, peer);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
    if (retval > 0 && peer && sk)
#else
    if (retval == 0 && peer && sk)
#endif
    {
        icsk = inet_csk(sk);
        if (icsk)
            info = (struct toa_sock_info *)icsk->icsk_ulp_data;

        if (info &&
            info->tdata.opcode == TCPOPT_TOA &&
            info->tdata.opsize == TCPOLEN_TOA) {
            TOA_INC_STATS(ext_stats, GETNAME_TOA_OK_CNT);
            sin->sin6_port = info->tdata.port;
            ipv6_addr_set(&sin->sin6_addr, 0, 0,
                          htonl(0x0000FFFF), info->tdata.ip);
        } else if (info) {
            TOA_INC_STATS(ext_stats, GETNAME_TOA_MISMATCH_CNT);
        } else {
            TOA_INC_STATS(ext_stats, GETNAME_TOA_EMPTY_CNT);
        }
    } else {
        TOA_INC_STATS(ext_stats, GETNAME_TOA_BYPASS_CNT);
    }

    return retval;
}
#endif /* CONFIG_IP_VS_TOA_IPV6 */

/* ============================================================
 *  SYN_RECV_SOCK hook（IPv4 / IPv6）
 * ============================================================
 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
static struct sock *
tcp_v4_syn_recv_sock_toa(const struct sock *sk, struct sk_buff *skb,
                         struct request_sock *req,
                         struct dst_entry *dst,
                         struct request_sock *req_unhash,
                         bool *own_req)
#else
static struct sock *
tcp_v4_syn_recv_sock_toa(struct sock *sk, struct sk_buff *skb,
                         struct request_sock *req, struct dst_entry *dst)
#endif
{
    struct sock *newsock;
    struct inet_request_sock *ireq = inet_rsk(req);
    __be16 dst_port;
    struct toa_data tdata;
    bool has_toa = false;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
    newsock = tcp_v4_syn_recv_sock(sk, skb, req, dst, req_unhash, own_req);
#else
    newsock = tcp_v4_syn_recv_sock(sk, skb, req, dst);
#endif

    if (!newsock)
        return newsock;

    dst_port = ireq->ir_num ? htons(ireq->ir_num) : tcp_hdr(skb)->dest;

    /* 修复版：只解析 TOA，不再分配/挂 sk_user_data */
    has_toa = get_toa_data(skb,
                           ireq->ir_rmt_addr, ireq->ir_rmt_port,
                           ireq->ir_loc_addr, dst_port,
                           &tdata);

    if (has_toa) {
        struct inet_connection_sock *icsk = inet_csk(newsock);
        struct toa_sock_info *info;

        if (icsk && !icsk->icsk_ulp_data) {
            info = kzalloc(sizeof(*info), GFP_ATOMIC);
            if (info) {
                info->tdata = tdata;
                info->orig_destruct = newsock->sk_destruct;
                icsk->icsk_ulp_data = info;
                newsock->sk_destruct = toa_sock_destruct;
                TOA_INC_STATS(ext_stats, SYN_RECV_SOCK_TOA_CNT);
                return newsock;
            }
        }
    }

    TOA_INC_STATS(ext_stats, SYN_RECV_SOCK_NO_TOA_CNT);
    return newsock;
}

#ifdef CONFIG_IP_VS_TOA_IPV6
static struct sock *
tcp_v6_syn_recv_sock_toa(struct sock *sk, struct sk_buff *skb,
                         struct request_sock *req, struct dst_entry *dst)
{
    struct sock *newsock;
    struct inet_request_sock *ireq = inet_rsk(req);
    __be16 dst_port;
    struct toa_data tdata;
    bool has_toa = false;

    newsock = tcp_v6_syn_recv_sock(sk, skb, req, dst);

    if (!newsock)
        return newsock;

    dst_port = ireq->ir_num ? htons(ireq->ir_num) : tcp_hdr(skb)->dest;

    has_toa = get_toa_data(skb,
                           ireq->ir_rmt_addr, ireq->ir_rmt_port,
                           ireq->ir_loc_addr, dst_port,
                           &tdata);

    if (has_toa) {
        struct inet_connection_sock *icsk = inet_csk(newsock);
        struct toa_sock_info *info;

        if (icsk && !icsk->icsk_ulp_data) {
            info = kzalloc(sizeof(*info), GFP_ATOMIC);
            if (info) {
                info->tdata = tdata;
                info->orig_destruct = newsock->sk_destruct;
                icsk->icsk_ulp_data = info;
                newsock->sk_destruct = toa_sock_destruct;
                TOA_INC_STATS(ext_stats, SYN_RECV_SOCK_TOA_CNT);
                return newsock;
            }
        }
    }

    TOA_INC_STATS(ext_stats, SYN_RECV_SOCK_NO_TOA_CNT);
    return newsock;
}
#endif /* CONFIG_IP_VS_TOA_IPV6 */

/* ============================================================
 *  HOOK / UNHOOK（仍使用原有的 x86 PTE RW 方法）
 * ============================================================
 */

extern const struct proto_ops inet_stream_ops;
extern const struct inet_connection_sock_af_ops ipv4_specific;
#ifdef CONFIG_IP_VS_TOA_IPV6
extern const struct proto_ops inet6_stream_ops;
extern const struct inet_connection_sock_af_ops ipv6_specific;
#endif

static inline int hook_toa_functions(void)
{
#if defined(CONFIG_X86)
    unsigned int level;
    pte_t *pte;
    struct proto_ops *inet_stream_ops_p =
        (struct proto_ops *)&inet_stream_ops;
    struct inet_connection_sock_af_ops *ipv4_specific_p =
        (struct inet_connection_sock_af_ops *)&ipv4_specific;
#ifdef CONFIG_IP_VS_TOA_IPV6
    struct proto_ops *inet6_stream_ops_p =
        (struct proto_ops *)&inet6_stream_ops;
    struct inet_connection_sock_af_ops *ipv6_specific_p =
        (struct inet_connection_sock_af_ops *)&ipv6_specific;
#endif

    /* 通过 PTE 方式把包含 inet_stream_ops 的页设为可写 */
    pte = lookup_address((unsigned long)inet_stream_ops_p, &level);
    if (!pte)
        return -EFAULT;
    if (!(pte->pte & _PAGE_RW))
        pte->pte |= _PAGE_RW;

    inet_stream_ops_p->getname = inet_getname_toa;
#ifdef CONFIG_IP_VS_TOA_IPV6
    inet6_stream_ops_p->getname = inet6_getname_toa;
#endif

    ipv4_specific_p->syn_recv_sock = tcp_v4_syn_recv_sock_toa;
#ifdef CONFIG_IP_VS_TOA_IPV6
    ipv6_specific_p->syn_recv_sock = tcp_v6_syn_recv_sock_toa;
#endif

    return 0;
#else
    return -EOPNOTSUPP;
#endif
}

static inline int unhook_toa_functions(void)
{
#if defined(CONFIG_X86)
    struct proto_ops *inet_stream_ops_p =
        (struct proto_ops *)&inet_stream_ops;
    struct inet_connection_sock_af_ops *ipv4_specific_p =
        (struct inet_connection_sock_af_ops *)&ipv4_specific;
#ifdef CONFIG_IP_VS_TOA_IPV6
    struct proto_ops *inet6_stream_ops_p =
        (struct proto_ops *)&inet6_stream_ops;
    struct inet_connection_sock_af_ops *ipv6_specific_p =
        (struct inet_connection_sock_af_ops *)&ipv6_specific;
#endif

    inet_stream_ops_p->getname = inet_getname;
#ifdef CONFIG_IP_VS_TOA_IPV6
    inet6_stream_ops_p->getname = inet6_getname;
#endif

    ipv4_specific_p->syn_recv_sock = tcp_v4_syn_recv_sock;
#ifdef CONFIG_IP_VS_TOA_IPV6
    ipv6_specific_p->syn_recv_sock = tcp_v6_syn_recv_sock;
#endif

    return 0;
#else
    return -EOPNOTSUPP;
#endif
}

/* ============================================================
 *  /proc/net/toa_stats
 * ============================================================
 */

static struct toa_stats_entry toa_stats[] = {
    TOA_STAT_ITEM("syn_recv_sock_toa",      SYN_RECV_SOCK_TOA_CNT),
    TOA_STAT_ITEM("syn_recv_sock_no_toa",   SYN_RECV_SOCK_NO_TOA_CNT),
    TOA_STAT_ITEM("getname_toa_ok",         GETNAME_TOA_OK_CNT),
    TOA_STAT_ITEM("getname_toa_mismatch",   GETNAME_TOA_MISMATCH_CNT),
    TOA_STAT_ITEM("getname_toa_bypass",     GETNAME_TOA_BYPASS_CNT),
    TOA_STAT_ITEM("getname_toa_empty",      GETNAME_TOA_EMPTY_CNT),
    TOA_STAT_END
};

static int toa_stats_show(struct seq_file *seq, void *v)
{
    int i, j, cpu_nr;

    seq_printf(seq, "                                  ");
    cpu_nr = num_possible_cpus();
    for (i = 0; i < cpu_nr; i++)
        if (cpu_online(i))
            seq_printf(seq, "CPU%d       ", i);
    seq_putc(seq, '\n');

    for (i = 0; toa_stats[i].name != NULL; i++) {
        seq_printf(seq, "%-25s:", toa_stats[i].name);
        for (j = 0; j < cpu_nr; j++) {
            if (cpu_online(j)) {
                struct toa_stat_mib *mib = per_cpu_ptr(ext_stats, j);
                seq_printf(seq, "%10lu ", mib->mibs[toa_stats[i].entry]);
            }
        }
        seq_putc(seq, '\n');
    }

    return 0;
}

static int toa_stats_seq_open(struct inode *inode, struct file *file)
{
    return single_open(file, toa_stats_show, NULL);
}

static const TOA_PROC_OPS toa_stats_fops = {
    TOA_PROC_OPEN    = toa_stats_seq_open,
    TOA_PROC_READ    = seq_read,
    TOA_PROC_LSEEK   = seq_lseek,
    TOA_PROC_RELEASE = single_release,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)
    .owner           = THIS_MODULE,
#endif
};

/* ============================================================
 *  /proc/net/toa_detail
 * ============================================================
 */

struct toa_detail_seq_state {
    struct toa_detail_entry *entries;
    unsigned long total_count;
    unsigned long current_index;
};

static int cmp_toa_detail(const void *a, const void *b)
{
    const struct toa_detail_entry *ea = a;
    const struct toa_detail_entry *eb = b;

    if (ea->timestamp.tv_sec < eb->timestamp.tv_sec)
        return -1;
    if (ea->timestamp.tv_sec > eb->timestamp.tv_sec)
        return 1;
    if (ea->timestamp.tv_nsec < eb->timestamp.tv_nsec)
        return -1;
    if (ea->timestamp.tv_nsec > eb->timestamp.tv_nsec)
        return 1;
    return 0;
}

static void *toa_detail_seq_start(struct seq_file *seq, loff_t *pos)
{
    struct toa_detail_seq_state *state = seq->private;
    int cpu, i;
    unsigned long start_pos, alloc_count, collected, global_index;
    unsigned long max_entries;

    if (!state)
        return NULL;

    if (*pos == 0) {
        state->entries       = NULL;
        state->total_count   = 0;
        state->current_index = 0;

        max_entries = toa_detail_total_max;

        /* 第一遍：加锁统计总条数 */
        for_each_possible_cpu(cpu) {
            struct toa_detail_fifo *fifo = per_cpu_ptr(toa_detail_fifos, cpu);
            unsigned long flags;
            int count;

            spin_lock_irqsave(&fifo->lock, flags);
            count = fifo->count;
            spin_unlock_irqrestore(&fifo->lock, flags);

            state->total_count += count;
        }

        if (state->total_count > max_entries)
            state->total_count = max_entries;

        if (state->total_count == 0)
            return NULL;

        start_pos = *pos;
        if (state->total_count > start_pos)
            alloc_count = state->total_count - start_pos;
        else
            alloc_count = 0;

        if (alloc_count == 0) {
            state->total_count = 0;
            return NULL;
        }

        state->entries = kvmalloc(alloc_count *
                                  sizeof(struct toa_detail_entry),
                                  GFP_KERNEL);
        if (!state->entries)
            return ERR_PTR(-ENOMEM);

        state->current_index = start_pos;
        collected   = 0;
        global_index = 0;

        /* 第二遍：加锁拷贝，保证 head/count 一致性 */
        for_each_possible_cpu(cpu) {
            struct toa_detail_fifo *fifo = per_cpu_ptr(toa_detail_fifos, cpu);
            unsigned long flags;
            int local_count, local_head;

            spin_lock_irqsave(&fifo->lock, flags);
            local_count = fifo->count;
            local_head  = fifo->head;

            for (i = 0; i < local_count; i++) {
                int index = (local_head + i) % fifo->size;

                if (global_index >= start_pos) {
                    if (collected >= alloc_count)
                        break;
                    state->entries[collected++] = fifo->entries[index];
                }

                global_index++;
                if (collected >= alloc_count)
                    break;
            }

            spin_unlock_irqrestore(&fifo->lock, flags);

            if (collected >= alloc_count)
                break;
        }

        state->total_count = collected;
        if (state->total_count == 0) {
            kvfree(state->entries);
            state->entries = NULL;
            return NULL;
        }

        sort(state->entries, state->total_count,
             sizeof(struct toa_detail_entry),
             cmp_toa_detail, NULL);
    }

    if (*pos >= state->current_index + state->total_count) {
        if (state->entries) {
            kvfree(state->entries);
            state->entries = NULL;
        }
        return NULL;
    }

    return &state->entries[*pos - state->current_index];
}

static void *toa_detail_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
    struct toa_detail_seq_state *state = seq->private;

    (*pos)++;
    if (*pos >= state->current_index + state->total_count) {
        if (state->entries) {
            kvfree(state->entries);
            state->entries = NULL;
        }
        return NULL;
    }

    return &state->entries[*pos - state->current_index];
}

static void toa_detail_seq_stop(struct seq_file *seq, void *v)
{
    /* 资源在 release 中统一释放 */
}

static int toa_detail_seq_show(struct seq_file *seq, void *v)
{
    struct toa_detail_entry *e = v;
    struct tm tm;
    long msecs;

    time64_to_tm(e->timestamp.tv_sec, 28800, &tm);
    msecs = e->timestamp.tv_nsec / 1000000;

    seq_printf(seq,
               "%04ld-%02d-%02d %02d:%02d:%02d.%03ld "
               "%u.%u.%u.%u:%u "
               "%u.%u.%u.%u:%u "
               "%u.%u.%u.%u:%u\n",
               tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
               tm.tm_hour, tm.tm_min, tm.tm_sec, msecs,
               NIPQUAD(e->toa_ip), ntohs(e->toa_port),
               NIPQUAD(e->src_ip), ntohs(e->src_port),
               NIPQUAD(e->dst_ip), ntohs(e->dst_port));

    return 0;
}

static const struct seq_operations toa_detail_seq_ops = {
    .start = toa_detail_seq_start,
    .next  = toa_detail_seq_next,
    .stop  = toa_detail_seq_stop,
    .show  = toa_detail_seq_show,
};

static int toa_detail_seq_open(struct inode *inode, struct file *file)
{
    struct seq_file *seq;
    int ret;

    ret = seq_open(file, &toa_detail_seq_ops);
    if (ret)
        return ret;

    seq = file->private_data;
    seq->private = kzalloc(sizeof(struct toa_detail_seq_state), GFP_KERNEL);
    if (!seq->private) {
        seq_release(inode, file);
        return -ENOMEM;
    }

    return 0;
}

static int toa_detail_seq_release(struct inode *inode, struct file *file)
{
    struct seq_file *seq = file->private_data;
    struct toa_detail_seq_state *state = seq->private;

    if (state && state->entries)
        kvfree(state->entries);
    kfree(state);

    return seq_release(inode, file);
}

static const TOA_PROC_OPS toa_detail_fops = {
    TOA_PROC_OPEN    = toa_detail_seq_open,
    TOA_PROC_READ    = seq_read,
    TOA_PROC_LSEEK   = seq_lseek,
    TOA_PROC_RELEASE = toa_detail_seq_release,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)
    .owner           = THIS_MODULE,
#endif
};

/* ============================================================
 *  MODULE INIT / EXIT
 * ============================================================
 */

static int __init toa_init(void)
{
    int cpu_nr = num_possible_cpus();
    struct proc_dir_entry *p1, *p2;
    int ret;

    if (toa_detail_fifo_size <= 0)
        toa_detail_fifo_size = 4096;

    if (toa_detail_total_max <= 0)
        toa_detail_total_max = toa_detail_fifo_size * cpu_nr;

    ext_stats = alloc_percpu(struct toa_stat_mib);
    if (!ext_stats) {
        ret = -ENOMEM;
        goto err_out;
    }

    ret = toa_detail_fifo_init_all();
    if (ret)
        goto err_stats;

    p1 = proc_create("toa_stats", 0, init_net.proc_net, &toa_stats_fops);
    if (!p1) {
        ret = -ENOMEM;
        goto err_fifo;
    }

    p2 = proc_create("toa_detail", 0, init_net.proc_net, &toa_detail_fops);
    if (!p2) {
        remove_proc_entry("toa_stats", init_net.proc_net);
        ret = -ENOMEM;
        goto err_fifo;
    }

    ret = hook_toa_functions();
    if (ret) {
        remove_proc_entry("toa_stats",  init_net.proc_net);
        remove_proc_entry("toa_detail", init_net.proc_net);
        goto err_fifo;
    }

    return 0;

err_fifo:
    toa_detail_fifo_destroy_all();
err_stats:
    if (ext_stats) {
        free_percpu(ext_stats);
        ext_stats = NULL;
    }
err_out:
    return ret;
}

static void __exit toa_exit(void)
{
    unhook_toa_functions();
    synchronize_net();

    remove_proc_entry("toa_stats",  init_net.proc_net);
    remove_proc_entry("toa_detail", init_net.proc_net);

    if (ext_stats) {
        free_percpu(ext_stats);
        ext_stats = NULL;
    }

    toa_detail_fifo_destroy_all();
}

module_init(toa_init);
module_exit(toa_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("SCTEL IBOC HuJie 2025-1209"); 
MODULE_DESCRIPTION("TCP Option Address (TOA) module for recording client IP/port"); 
