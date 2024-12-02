# 環境確認
- `cat /etc/os-release`
    ```sh
    NAME="AlmaLinux"
    VERSION="8.10 (Cerulean Leopard)"
    ID="almalinux"
    ID_LIKE="rhel centos fedora"
    VERSION_ID="8.10"
    PLATFORM_ID="platform:el8"
    PRETTY_NAME="AlmaLinux 8.10 (Cerulean Leopard)"
    ANSI_COLOR="0;34"
    LOGO="fedora-logo-icon"
    CPE_NAME="cpe:/o:almalinux:almalinux:8::baseos"
    HOME_URL="https://almalinux.org/"
    DOCUMENTATION_URL="https://wiki.almalinux.org/"
    BUG_REPORT_URL="https://bugs.almalinux.org/"

    ALMALINUX_MANTISBT_PROJECT="AlmaLinux-8"
    ALMALINUX_MANTISBT_PROJECT_VERSION="8.10"
    REDHAT_SUPPORT_PRODUCT="AlmaLinux"
    REDHAT_SUPPORT_PRODUCT_VERSION="8.10"
    SUPPORT_END=2029-06-01
    ```

- `uname -r`
    ```sh
    4.18.0-553.5.1.el8_10.x86_64
    ```

- SELinuxの設定
    ```sh
    #無効にする
    sudo vim /etc/selinux/config
    SELINUX=enforcing
    ↓
    SELINUX=disabled

    # SELinuxの状態確認
    $ getenforce
    Enforcing (SELinux有効/アクセス制限有効)

    # SELinuxの無効化（一時的）
    $ sudo setenforce 0
    [sudo] password for akihiro: 

    # SELinuxの設定を確認
    $ getenforce
    Permissive (SELinuxは有効/アクセス制限は実施しない(警告出力))
    ```

# VNICの設定
- 既に作成されたカーネルモジュールをカーネルにロード
    ```sh
    sudo insmod vnic/vnic.ko
    ```
- VNICにIPアドレスを設定
    ```sh
    sudo ip addr add 192.168.1.10/24 dev VNIC-mizuno
    sudo ip addr add 172.20.1.10/24 dev VNIC-mizuno
    ```
- 仮想NICを有効化
    ```sh
    sudo ip link set VNIC-mizuno up
    ```
- デフォルトゲートウェイの設定（元の物理NICがデフォルトに存在している）
    ```sh
    # 追加
    sudo ip route add default via 192.168.1.1 dev VNIC-mizuno
    sudo ip route add default via 172.20.1.1 dev VNIC-mizuno

    # 削除
    sudo ip route del default via 192.168.0.1 dev enp0s31f6
    sudo ip route del default via 172.20.10.1 dev wlp2s0

    # エラー「Error: Nexthop has invalid gateway.」などの際は、ルートテーブルのキャッシュの削除が一つの解決策
    sudo ip route flush cache
    その後再度デフォルトを設定（失敗した場合、VNICに割り当てたIPアドレスも消える場合もあり）
    # キャッシュ削除で治らない場合同じサブネットに属していない可能性がある。/24などに注意して確認すべき
    ```

- カーネルのフォワーディングの無効化を確認
    ```sh
    # 1だと有効化されている
    cat /proc/sys/net/ipv4/ip_forward

    #無効化方法
    sudo vim /etc/sysctl.conf
    [追記]net.ipv4.ip_forward = 0
    sudo sysctl -p /etc/sysctl.conf #設定を適用

    #一時的な無効化方法
    sudo sysctl -w net.ipv4.ip_forward=0
    ```

- ネットワークマネージャーを止める
    ```sh
    sudo systemctl disable NetworkManager
    ```

- arp確認方法
    ```sh
    ip neigh show
    ```

- ファイアウォールの設定
    ```sh
    # 設定を確認
    sudo firewall-cmd --list-all

    # forwardが[no]の場合、通信を妨害しているため修正する
    sudo firewall-cmd --zone=public --add-forward --permanent
    sudo firewall-cmd --reload

    # 信頼ゾーンに仮想NICと物理NICの両方を追加
    sudo firewall-cmd --zone=trusted --add-interface=enp0s31f6 --permanent
    sudo firewall-cmd --zone=trusted --add-interface=VNIC-mizuno --permanent
    sudo firewall-cmd --reload

    # 最終手段 - ファイアウォールを一時停止
    sudo systemctl stop firewalld
    ```

# bridge操作
- 物理NICからIPを消す
    ```sh
    sudo ip addr flush dev enp0s31f6
    ```

- コンパイルと起動
    ```sh
    gcc -o bridge_mz bridge_mz.c
    sudo ./bridge_mz
    ```

# 確認用コマンド
- ゲートウェイへの接続確認
    ```sh
    ping -I VNIC-mizuno 192.168.1.1
    ```
