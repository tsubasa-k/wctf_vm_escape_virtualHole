# QEMU Virtio-SCSI VM Escape漏洞驗證(PoC)
利用 QEMU 2.6.0 版本中 virtqueue_map_desc 函數對異常描述符長度處理不當，導致的 空指標引用 (Null Pointer Dereference)，進而造成宿主機 (Host) 的 QEMU 進程崩潰 (DoS)。

## 前置要求
- QEMU 版本：QEMU 2.6.0 或 2.6.0-rc2（新版已修復）
- 目標設備: virtio-scsi-pci
- Guest OS : Linux (Ubuntu 16.04)
- Host OS : Linux (Ubuntu)
- 啟動參數：必須包含 -device virtio-scsi-pci,id=scsi0

## 第一階段：環境準備 (Host OS)
假設宿主機（Host）是 Ubuntu 16.04（或您在 VMware 中運行的 Ubuntu 16.04）。

1. 安裝編譯依賴
參考 GitHub README 和 PDF 中的列表，安裝編譯 QEMU 和 Linux Kernel Module 所需的套件。
```
sudo apt-get update
# 安裝 QEMU 編譯依賴
sudo apt-get install -y zlib1g-dev libglib2.0-dev autoconf libtool libgtk2.0-dev flex bison
# 安裝 KVM 相關 (確保虛擬化正常)
sudo apt-get install -y qemu-kvm build-essential
```

2. 下載並編譯特定版本的 QEMU
如果使用 GitHub 推薦的 QEMU 4.0.0，此漏洞可能已被修復。
```
# 下載 QEMU 2.6.0
wget https://download.qemu.org/qemu-2.6.0.tar.xz
tar -jxvf qemu-2.6.0-rc2.tar.xz
cd qemu-2.6.0

# 配置編譯選項 (開啟 debug 方便除錯)
./configure --enable-kvm --enable-debug --target-list=x86_64-softmmu

# 編譯並安裝
make -j4
sudo make install
````

## 第二階段：建立虛擬機 (Guest OS)
我們需要安裝一個 Ubuntu 16.04 Server 作為 Guest OS，用來執行攻擊腳本。

1. 建立硬碟映像檔
```
# 建立 20G 的硬碟
qemu-img create -f qcow2 ubuntu-server.img 20G
```
2. 安裝 Ubuntu 16.04 Server
請確保有 ubuntu-16.04.x-server-amd64.iso 檔案。
```
# 啟動並安裝系統
qemu-system-x86_64 -m 2048 -hda ubuntu-server.img -cdrom ubuntu-16.04.x-server-amd64.iso -enable-kvm
```
  
## 攻擊程式碼 (poc.c)
請在虛擬機 (Guest OS) 中建立此檔案。此代碼會構造一個帶有惡意長度 (0x44444444) 的描述符鏈，並發送 SCSI INQUIRY 指令來觸發 QEMU 的數據寫回操作，引發崩潰。

注意：請務必先在虛擬機執行 lspci -v 查看 Virtio SCSI 的 I/O ports 地址，並修改程式碼中的 #define VIRTIO_SCSI_IO。

## 第三階段：執行與驗證
1. 在Host OS上啟動QEMU 
```
./qemu-2.6.0/x86_64-softmmu/qemu-system-x86_64 \
  -enable-kvm \
  -m 2048 \
  -hda ubuntu-server2.img \
  -device virtio-scsi-pci,id=scsi0 \
  -net user,hostfwd=tcp::2222-:22 \
  -net nic
```

2. 在 Guest OS 中編譯模組：
在虛擬機內部，使用Makefile編譯exploit.c。
```
# 成功後會生成 poc.ko
make
```

3. 載入模組進行攻擊：
```
sudo insmod poc.ko
```

## 預期結果： 
- Guest OS 可能會卡死。
- 切換回 Host OS 的終端機（運行 QEMU 的視窗），應該會看到 QEMU 進程崩潰（Segmentation Fault）

漏洞原理簡述： 該漏洞發生在 virtqueue_pop -> virtqueue_map_desc -> cpu_physical_memory_map 的路徑中。當描述符的長度過大時，QEMU 內部的映射函數可能會失敗並返回 NULL，但後續的 address_space_unmap 邏輯中，對於 bounce.buffer 為 NULL 的情況處理不當，導致了空指標引用（Dereference）或對 NULL 地址的 memcpy，造成 QEMU 進程崩潰



