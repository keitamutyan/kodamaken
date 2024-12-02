# 環境確認
- `cat /etc/os-release`や`uname -r`を使用してOSやカーネルのバージョンを確認する

# vnic作業
- 環境に基づいてカーネルモジュール作成に必要なモジュールをインストールする
    ```sh
    sudo dnf install kernel-devel-$(uname -r) kernel-headers-$(uname -r) gcc make
    ```
- vnicのコードを入れたファイルを名前は任意で作成（今回はvnic.c）
- Makefileを作成
    ```makefile
    obj-m += vnic.o

    all:
        make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

    clean:
        make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

    ```
- 念の為カーネルソースのインストールを確認。ディレクトリ内に`Makefile`や`Kconfig`があるか確認。
    ```sh
    ls /lib/modules/$(uname -r)/build
    ```
- 先ほど作ったMakefileを使用してコンパイルしカーネルモジュール作成
    ```sh
    make
    ```
    いろいろなファイルが生成されるが、これによりカーネルモジュール`vnic.ko`というカーネルモジュールファイルが生成されているか特に確認する。
- カーネルモジュールをカーネルにロードする
    ```sh
    sudo insmod vnic.ko
    ```
- カーネルログからロードを確認
    ```sh
    dmesg | tail
    ---------------
    (以下ログ例)
    [118720.621012] IPv6: ADDRCONF(NETDEV_UP): Supervisor: link is not ready
    # 説明
    # これは、デバイスが「up」状態にされたが、まだリンクが確立されていない（物理接続や他の設定が完了していない）ことを示している。これは、仮想ネットワークデバイスの初期状態として問題ない状態らしい
    ```
- 仮想ネットワークインターフェースが認識されたか正しく認識されているか確認
    ```
    ip link show
    --------------
    (以下ログ例)
    5: Supervisor: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN mode DEFAULT group default qlen 1000
    link/ether 00:00:00:00:00:01 brd ff:ff:ff:ff:ff:ff
    ```
