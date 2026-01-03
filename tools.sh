#!/bin/bash

# ANSI 颜色代码
green='\033[0;32m'
plain='\033[0m'

# 显示绿色横幅
echo -e "${green}"
echo "                                                                   "
echo "                                       bbbbbbbb                    "
echo "                                       b::::::b                    "
echo "                                       b::::::b                    "
echo "                                       b::::::b                    "
echo "                                        b:::::b                    "
echo "rrrrr   rrrrrrrrr       eeeeeeeeeeee    b:::::bbbbbbbbb            "
echo "r::::rrr:::::::::r    ee::::::::::::ee  b::::::::::::::bb          "
echo "r:::::::::::::::::r  e::::::eeeee:::::eeb::::::::::::::::b         "
echo "rr::::::rrrrr::::::re::::::e     e:::::eb:::::bbbbb:::::::b        "
echo " r:::::r     r:::::re:::::::eeeee::::::eb:::::b    b::::::b        "
echo " r:::::r     rrrrrrre:::::::::::::::::e b:::::b     b:::::b        "
echo " r:::::r            e::::::eeeeeeeeeee  b:::::b     b:::::b        "
echo " r:::::r            e:::::::e           b:::::b     b:::::b        "
echo " r:::::r            e::::::::e          b:::::bbbbbb::::::b        "
echo " r:::::r             e::::::::eeeeeeee  b::::::::::::::::b  ...... "
echo " r:::::r              ee:::::::::::::e  b:::::::::::::::b   .::::. "
echo " rrrrrrr                eeeeeeeeeeeeee  bbbbbbbbbbbbbbbb    ...... "

echo -e "${plain}"


# 版本号
VERSION="1.2"	

# 获取当前脚本的路径
SCRIPT_PATH="$(cd "$(dirname "$0")" && pwd -P)"
SCRIPT_NAME=$(basename "$0")

# 判断是否为第一次运行脚本  
if [ ! -f "/usr/local/bin/$SCRIPT_NAME" ]; then
    # 将脚本移动到 /usr/local/bin 目录
    sudo mv "$SCRIPT_PATH/$SCRIPT_NAME" /usr/local/bin/
    # 添加执行权限
    sudo chmod +x "/usr/local/bin/$SCRIPT_NAME"
    # 提示用户脚本已经被移动
    echo "脚本已移动到 /usr/local/bin 目录并添加执行权限"
    echo "您可以直接在命令行中使用 $SCRIPT_NAME 打开脚本"
    exit 0
fi

# 检查更新函数
update() {
    echo "检查更新..."  # 提示用户正在进行更新检查操作
    # 获取远程版本号
    REMOTE_VERSION=$(curl -s https://raw.githubusercontent.com/xxy0op/gongju/master/version.txt)
    if [[ -n "$REMOTE_VERSION" ]]; then  # 检查是否成功获取远程版本号
        if [[ "$REMOTE_VERSION" != "$VERSION" ]]; then
            echo "发现新版本 $REMOTE_VERSION,是否更新?[Y/n]"
            read -r response
            if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
                # 下载新版本的脚本
                wget -q https://raw.githubusercontent.com/xxy0op/gongju/master/tools.sh -O tools.sh.new
                if [[ -s "tools.sh.new" ]]; then  # 检查是否成功下载新版本的脚本
                    # 备份旧版本
                    mv /usr/local/bin/tools.sh /usr/local/bin/tools.sh.old
                    # 将新版本移动到正确的位置
                    mv tools.sh.new /usr/local/bin/tools.sh
                    # 添加执行权限
                    chmod +x /usr/local/bin/tools.sh
                    echo "更新完成,重新运行脚本..."
                    exec "/usr/local/bin/tools.sh" "$@"
                else
                    echo "下载新版本失败,无法更新。"
                fi
            fi
        else 
            echo "已经是最新版本。"
        fi
    else
        echo "无法获取远程版本信息,检查网络连接或稍后重试。"
    fi
}

# 卸载脚本函数
uninstall_script() {
    echo "确定要卸载脚本吗? [默认n]:"
    read -r uninstall_response
    if [[ "$uninstall_response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        echo "卸载成功!"
        # 删除脚本文件
        rm "/usr/local/bin/$SCRIPT_NAME" -f
        echo "脚本文件已成功删除。"
        exit 0
    else
        echo "取消卸载。"
    fi
}

# 获取当前版本号函数
get_version() {
    echo -e "\e[32m当前版本号:$VERSION\e[34m"
}

# 安装 XrayR 脚本
xrayr() {
    echo "正在安装 XrayR 脚本..."
    # 执行 XrayR 安装脚本
    bash <(curl -Ls https://raw.githubusercontent.com/XrayR-project/XrayR-release/master/install.sh) 0.9.0
}

# 安装 Warp 脚本
warp() {
    echo "正在安装 Warp 脚本..."
    # 下载并执行 Warp 安装脚本
    wget -N https://gitlab.com/fscarmen/warp/-/raw/main/menu.sh && bash menu.sh
}

# 安装 speedtest 脚本
speedtest() {
    echo "正在安装 speedtest 脚本..."
    # 安装 curl
    sudo apt-get install -y curl
    # 安装 speedtest-cli
    curl -s https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh | sudo bash
    sudo apt-get install -y speedtest
}

# 优化网络性能函数 - 专为SS节点优化
network_optimize() {
    echo "========== SS节点网络性能优化 =========="
    
    # 计算系统内存相关参数
    # 获取系统总内存(KB)
    total_mem=$(cat /proc/meminfo | grep MemTotal | awk '{print $2}')
    # 计算TCP内存参数 (基于总内存)
    t_size=$((total_mem * 1024))
    t_min=$(printf '%d' $(($t_size / 4096 / 4 * 1)))
    t_avg=$(printf '%d' $(($t_size / 4096 / 4 * 2)))
    t_max=$(printf '%d' $(($t_size / 4096 / 4 * 3)))
    
    echo "系统总内存: $total_mem KB"
    echo "TCP内存参数: $t_min $t_avg $t_max"
    echo "使用BBR拥塞控制算法"
    
    # 选择优化级别
    echo "请选择优化级别:"
    echo "1. 基础优化 (适合小内存VPS, <1GB)"
    echo "2. 标准优化 (适合大多数情况, 1-4GB内存)"
    echo "3. 极致优化 (适合4GB以上内存)"
    read -p "请选择 [2]: " opt_level
    opt_level=${opt_level:-2}
    
    case $opt_level in
        1)
            echo "应用基础优化参数..."
            # 小内存VPS的参数
            rmem_max="8388608"    # 8MB
            wmem_max="8388608"    # 8MB
            backlog="8192"
            ;;
        3)
            echo "应用极致优化参数..."
            # 大内存服务器的参数
            rmem_max="67108864"   # 64MB
            wmem_max="67108864"   # 64MB
            backlog="1048576"
            ;;
        *)
            echo "应用标准优化参数..."
            # 标准参数
            rmem_max="33554432"   # 32MB
            wmem_max="33554432"   # 32MB
            backlog="262144"
            ;;
    esac
    
    # 准备sysctl参数
    declare -A params=(
        # TCP拥塞控制 - 默认BBR
        ["net.ipv4.tcp_congestion_control"]="bbr"
        ["net.core.default_qdisc"]="fq"
        
        # 基本网络配置
        ["net.ipv4.ip_forward"]="1"
        ["net.ipv4.tcp_fastopen"]="3"
        ["net.ipv4.tcp_mtu_probing"]="1"
        ["net.ipv4.tcp_slow_start_after_idle"]="0"
        
        # TCP窗口优化
        ["net.ipv4.tcp_window_scaling"]="1"
        ["net.ipv4.tcp_adv_win_scale"]="-2"
        ["net.ipv4.tcp_timestamps"]="1"
        ["net.ipv4.tcp_sack"]="1"
        ["net.ipv4.tcp_dsack"]="1"
        ["net.ipv4.tcp_fack"]="1"
        ["net.ipv4.tcp_no_metrics_save"]="1"
        
        # 内存优化
        ["net.ipv4.tcp_rmem"]="4096 87380 ${rmem_max}"
        ["net.ipv4.tcp_wmem"]="4096 65536 ${wmem_max}"
        ["net.core.rmem_max"]="${rmem_max}"
        ["net.core.wmem_max"]="${wmem_max}"
        ["net.core.rmem_default"]="1048576"
        ["net.core.wmem_default"]="1048576"
        ["net.ipv4.udp_rmem_min"]="8192"
        ["net.ipv4.udp_wmem_min"]="8192"
        ["net.ipv4.tcp_mem"]="${t_min} ${t_avg} ${t_max}"
        ["net.ipv4.udp_mem"]="${t_min} ${t_avg} ${t_max}"
        
        # 连接优化
        ["net.core.somaxconn"]="65535"
        ["net.ipv4.tcp_max_syn_backlog"]="${backlog}"
        ["net.core.netdev_max_backlog"]="${backlog}"
        ["net.ipv4.tcp_max_tw_buckets"]="65535"
        ["net.ipv4.ip_local_port_range"]="1024 65535"
        
        # 安全参数
        ["net.ipv4.tcp_syncookies"]="1"
        ["net.ipv4.conf.all.rp_filter"]="1"
        ["net.ipv4.conf.default.rp_filter"]="1"
        ["net.ipv4.conf.all.accept_source_route"]="0"
        ["net.ipv4.conf.default.accept_source_route"]="0"
        ["net.ipv4.conf.all.accept_redirects"]="0"
        ["net.ipv4.conf.default.accept_redirects"]="0"
        
        # 系统资源优化
        ["kernel.pid_max"]="4194304"
        ["fs.file-max"]="1048576"
        ["fs.protected_hardlinks"]="1"
        ["fs.protected_symlinks"]="1"
        
        # IPv6相关
        ["net.ipv6.conf.all.disable_ipv6"]="1"
        ["net.ipv6.conf.default.disable_ipv6"]="1"
        ["net.ipv6.conf.lo.disable_ipv6"]="1"
        
        # 延迟优化
        ["net.ipv4.tcp_keepalive_time"]="600"
        ["net.ipv4.tcp_keepalive_intvl"]="30"
        ["net.ipv4.tcp_keepalive_probes"]="10"
        ["net.ipv4.tcp_fin_timeout"]="30"
        
        # 虚拟内存 - 固定设置为4096
        ["vm.swappiness"]="10"
        ["vm.min_free_kbytes"]="4096"
    )
    
    # 备份原始配置
    if [ ! -f "/etc/sysctl.conf.bak" ]; then
        echo "备份原始sysctl配置..."
        cp /etc/sysctl.conf /etc/sysctl.conf.bak
    fi
    
    # 应用sysctl参数到/etc/sysctl.conf
    echo "正在应用网络优化参数..."
    
    for param in "${!params[@]}"; do
        value=${params[$param]}
        # 更新/etc/sysctl.conf文件
        if grep -q "^$param" /etc/sysctl.conf; then
            # 如果存在,则使用sed命令更新其值
            sed -i "s/^$param.*/$param = $value/" /etc/sysctl.conf
        else
            # 如果不存在,则追加到文件末尾
            echo "$param = $value" >> /etc/sysctl.conf
        fi
    done
    
    # 设置文件描述符限制
    if ! grep -q "nofile" /etc/security/limits.conf; then
        echo "设置文件描述符限制..."
        cat >> /etc/security/limits.conf << EOF
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
* soft nproc 1048576
* hard nproc 1048576
EOF
    fi
    
    # 应用所有sysctl参数
    echo "正在应用所有网络参数..."
    sysctl -p
    
    if [ $? -eq 0 ]; then
        echo -e "\033[32m✓ 网络优化参数应用成功!\033[0m"
        echo "当前拥塞控制算法: $(sysctl -n net.ipv4.tcp_congestion_control)"
        echo "当前队列算法: $(sysctl -n net.core.default_qdisc)"
        echo "TCP Fast Open: $(sysctl -n net.ipv4.tcp_fastopen)"
        echo "vm.min_free_kbytes: 4096 (固定值)"
    else
        echo -e "\033[31m× 部分参数应用失败,请检查日志\033[0m"
    fi
    
    # 询问是否需要重启
    echo
    echo "注意: 某些参数可能需要重启服务器才能完全生效"
    read -p "是否现在重启服务器? [y/N]: " restart_response
    if [[ "$restart_response" =~ ^([yY][eE][sS]|[yY])+$ ]]; then
        echo "服务器将在3秒后重启..."
        sleep 3
        reboot
    else
        echo "跳过重启。您可以稍后手动重启服务器以确保所有参数生效。"
    fi
}

# 安装 nxtrace 脚本
nxtrace() {
    echo "正在安装 nxtrace 脚本..."
    # 使用 curl 下载 nt 脚本并执行
    curl nxtrace.org/nt | bash
}

#安装realm脚本
realm() {
    bash <(curl -sL download.tapby.de/realm/install.sh)
}

# 安装DDNS脚本
ddns() {
    echo "正在下载并运行 Cloudflare DDNS 脚本..."
    # 下载 Cloudflare DDNS 脚本
    wget -O /root/cloudflareddns.sh https://raw.githubusercontent.com/xxy0op/cloudflareddns/main/cloudflareddns.sh
    # 添加执行权限
    chmod +x /root/cloudflareddns.sh
    # 执行 Cloudflare DDNS 脚本
    /root/cloudflareddns.sh
}

# 运行NodeQuality脚本
NodeQuality() {
    echo "运行NodeQuality测试脚本..."
    # 下载并执行NodeQuality测试脚本
    bash <(curl -sL https://run.NodeQuality.com)
}

# 添加swap分区函数
swap() {
    echo "开始创建swap分区"

    # 获取用户输入的swap分区大小(单位:GB)
    read -p "请输入要创建的swap分区大小(单位:GB):" swap_size_gb
    # 将GB转换为MB
    swap_size_mb=$((swap_size_gb * 1024))
    # 检查输入是否为正整数
    if ! [[ $swap_size_gb =~ ^[0-9]+$ ]]; then
        echo "错误:请输入一个正整数。"
        return 1
    fi

    echo "1. Create ${swap_size_gb}GB 大小的分区"
    # 创建swap分区文件
    dd if=/dev/zero of=/root/swapfile bs=1M count="$swap_size_mb"

    echo "2. Format newly created partition file"
    # 格式化新建的swap分区文件
    mkswap /root/swapfile

    echo "3. Set the newly created partition file as a SWAP partition"
    # 将新建的分区文件设为swap分区
    swapon /root/swapfile

    echo "4. Set the swap partition to be automatically mounted at startup"
    # 设置开机自动挂载swap分区
    echo "/root/swapfile swap swap defaults 0 0" >> /etc/fstab

    echo "5. After the partition is created, you can enter free -h to view the partition."
    # 查看分区情况
    free -h
}

# 安装 bt 
bt() {
    echo "正在安装宝塔脚本..."
    # 下载并执行宝塔安装脚本
URL=https://www.aapanel.com/script/install_7.0_en.sh && if [ -f /usr/bin/curl ];then curl -ksSO "$URL" ;else wget --no-check-certificate -O install_7.0_en.sh "$URL";fi;bash install_7.0_en.sh aapanel
}

#安装 docker 和 docker compose
docker() {
    echo "正在安装 Docker..."
    curl -fsSL https://get.docker.com | sh
    echo "正在安装 Docker Compose..."
    DOCKER_CONFIG=${DOCKER_CONFIG:-$HOME/.docker}
    mkdir -p $DOCKER_CONFIG/cli-plugins
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) ARCH="x86_64" ;;
        aarch64) ARCH="aarch64" ;;
        armv7l) ARCH="armv7" ;;
        *) ARCH="x86_64" ;;
    esac
    VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep tag_name | cut -d '"' -f 4)
    curl -SL https://github.com/docker/compose/releases/download/${VERSION}/docker-compose-linux-${ARCH} -o $DOCKER_CONFIG/cli-plugins/docker-compose
    chmod +x $DOCKER_CONFIG/cli-plugins/docker-compose
    echo "Docker 和 Docker Compose 安装完成!"
}

#安装 python
python() {
    apt install python3-full -y
    apt install python3-dev -y
    apt install python3-venv -y
    apt install pipx -y
    pipx ensurepath
}

# SSH安全配置功能 - 禁用密码登录,启用密钥登录
ssh_security() {
    echo "========== SSH安全配置 =========="
    echo "此功能将会:"
    echo "1. 禁用SSH密码登录"
    echo "2. 启用SSH密钥登录"
    echo ""
    echo -e "\033[31m警告: 在继续之前,请确保您已经设置了SSH密钥!\033[0m"
    echo -e "\033[31m如果没有密钥,您可能会失去服务器访问权限!\033[0m"
    echo ""
    
    # 检查是否已存在授权密钥
    if [ ! -f ~/.ssh/authorized_keys ] || [ ! -s ~/.ssh/authorized_keys ]; then
        echo -e "\033[33m检测到您还没有设置SSH密钥。\033[0m"
        read -p "是否现在添加SSH公钥?[Y/n]: " add_key_response
        add_key_response=${add_key_response:-Y}
        
        if [[ "$add_key_response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
            # 创建.ssh目录
            mkdir -p ~/.ssh
            chmod 700 ~/.ssh
            
            echo "请输入您的SSH公钥内容(通常以ssh-rsa、ssh-ed25519等开头):"
            read -r ssh_public_key
            
            if [ -n "$ssh_public_key" ]; then
                echo "$ssh_public_key" >> ~/.ssh/authorized_keys
                chmod 600 ~/.ssh/authorized_keys
                echo -e "\033[32m✓ SSH公钥已添加到authorized_keys\033[0m"
            else
                echo -e "\033[31m× 未输入有效的公钥,操作取消\033[0m"
                return 1
            fi
        else
            echo -e "\033[31m× 没有SSH密钥的情况下禁用密码登录是危险的,操作取消\033[0m"
            return 1
        fi
    else
        echo -e "\033[32m✓ 检测到已存在SSH密钥\033[0m"
    fi
    
    # 最终确认
    echo ""
    echo "即将进行以下配置:"
    echo "- 禁用密码登录"
    echo "- 启用公钥认证"
    echo ""
    read -p "确认继续?[y/N]: " final_confirm
    
    if [[ ! "$final_confirm" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        echo "操作取消"
        return 0
    fi
    
    # 备份原始SSH配置
    if [ ! -f "/etc/ssh/sshd_config.bak" ]; then
        echo "备份原始SSH配置..."
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
    fi
    
    # 应用SSH安全配置
    echo "正在应用SSH安全配置..."
    
    SSH_CONFIG="/etc/ssh/sshd_config"
    
    # 禁用密码认证
    sed -i 's/^#*PasswordAuthentication .*/PasswordAuthentication no/' $SSH_CONFIG
    if ! grep -q "^PasswordAuthentication" $SSH_CONFIG; then
        echo "PasswordAuthentication no" >> $SSH_CONFIG
    fi
    
    # 启用公钥认证
    sed -i 's/^#*PubkeyAuthentication .*/PubkeyAuthentication yes/' $SSH_CONFIG
    if ! grep -q "^PubkeyAuthentication" $SSH_CONFIG; then
        echo "PubkeyAuthentication yes" >> $SSH_CONFIG
    fi
    
    # 测试SSH配置
    echo "测试SSH配置语法..."
    if sshd -t; then
        echo -e "\033[32m✓ SSH配置语法正确\033[0m"
        
        # 重启SSH服务
        echo "重启SSH服务..."
        systemctl restart sshd
        
        if systemctl is-active --quiet sshd; then
            echo -e "\033[32m✓ SSH服务重启成功\033[0m"
            echo ""
            echo "========== 配置完成 =========="
            echo -e "\033[32m✓ SSH密码登录已禁用\033[0m"
            echo -e "\033[32m✓ SSH密钥登录已启用\033[0m"
            echo ""
            echo -e "\033[31m重要提醒:\033[0m"
            echo "1. 请不要关闭当前SSH连接"
            echo "2. 请在新终端中测试SSH密钥登录"
            echo "3. 确认可以正常登录后再关闭当前会话"
        else
            echo -e "\033[31m× SSH服务重启失败\033[0m"
            echo "恢复原始配置..."
            cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
            systemctl restart sshd
        fi
    else
        echo -e "\033[31m× SSH配置语法错误,恢复原始配置\033[0m"
        cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
    fi
}

#安装ufw-docker
add_ufw_docker_rules() {
    echo "正在将 UFW Docker 规则添加到 /etc/ufw/after.rules 文件底部..."

    ufw_rules_file="/etc/ufw/after.rules"

    # 定义要添加的规则内容
    read -r -d '' RULES << 'EOF'
# BEGIN UFW AND DOCKER
*filter
:ufw-user-forward - [0:0]
:ufw-docker-logging-deny - [0:0]
:DOCKER-USER - [0:0]
-A DOCKER-USER -j ufw-user-forward

-A DOCKER-USER -j RETURN -s 10.0.0.0/8
-A DOCKER-USER -j RETURN -s 172.16.0.0/12
-A DOCKER-USER -j RETURN -s 192.168.0.0/16

-A DOCKER-USER -p udp -m udp --sport 53 --dport 1024:65535 -j RETURN

-A DOCKER-USER -j ufw-docker-logging-deny -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -d 192.168.0.0/16
-A DOCKER-USER -j ufw-docker-logging-deny -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -d 10.0.0.0/8
-A DOCKER-USER -j ufw-docker-logging-deny -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -d 172.16.0.0/12
-A DOCKER-USER -j ufw-docker-logging-deny -p udp -m udp --dport 0:32767 -d 192.168.0.0/16
-A DOCKER-USER -j ufw-docker-logging-deny -p udp -m udp --dport 0:32767 -d 10.0.0.0/8
-A DOCKER-USER -j ufw-docker-logging-deny -p udp -m udp --dport 0:32767 -d 172.16.0.0/12

-A DOCKER-USER -j RETURN

-A ufw-docker-logging-deny -m limit --limit 3/min --limit-burst 10 -j LOG --log-prefix "[UFW DOCKER BLOCK] "
-A ufw-docker-logging-deny -j DROP

COMMIT
# END UFW AND DOCKER
EOF

    # 检查是否已添加过
    if grep -q "# BEGIN UFW AND DOCKER" "$ufw_rules_file"; then
        echo "UFW Docker 配置已存在,跳过添加。"
    else
        echo "$RULES" | sudo tee -a "$ufw_rules_file" > /dev/null
        echo "已成功添加规则,正在重启 UFW 服务..."
        sudo systemctl restart ufw
        echo "UFW 服务已重启完成。"
    fi
}

# 带宽限速功能
bandwidth_limit() {
    IFACE="eth0"
    IFB_DEV="ifb0"

    while true; do
        echo "===== 带宽限速功能 ====="
        echo "1. 启用限速"
        echo "2. 取消限速"
        echo "0. 返回"
        read -p "请选择一个选项:" limit_choice
        case $limit_choice in
            1)
                read -p "请输入限速带宽(单位Mbps,例如 200): " RATE
                RATE="${RATE}mbit"

                echo ">> 正在配置限速,限速值: $RATE"

                # 加载 ifb 模块
                modprobe ifb numifbs=1

                # 启动 ifb 设备
                ip link set dev $IFB_DEV up 2>/dev/null || ip link add $IFB_DEV type ifb && ip link set $IFB_DEV up

                # 清除原有规则
                tc qdisc del dev $IFACE root 2>/dev/null
                tc qdisc del dev $IFACE ingress 2>/dev/null
                tc qdisc del dev $IFB_DEV root 2>/dev/null

                # 上行限速
                tc qdisc add dev $IFACE root handle 1: htb default 11
                tc class add dev $IFACE parent 1: classid 1:11 htb rate $RATE ceil $RATE burst 4mb
                tc filter add dev $IFACE protocol ip parent 1:0 prio 1 u32 match ip src 0.0.0.0/0 flowid 1:11

                # 下行限速
                tc qdisc add dev $IFACE handle ffff: ingress
                tc filter add dev $IFACE parent ffff: protocol ip u32 match u32 0 0 action mirred egress redirect dev $IFB_DEV
                tc qdisc add dev $IFB_DEV root handle 2: htb default 22
                tc class add dev $IFB_DEV parent 2: classid 2:22 htb rate $RATE ceil $RATE burst 4mb

                echo ">> 限速配置完成,当前上下行限速 $RATE"
                ;;
            2)
                echo ">> 正在取消限速..."
                tc qdisc del dev $IFACE root 2>/dev/null
                tc qdisc del dev $IFACE ingress 2>/dev/null
                tc qdisc del dev $IFB_DEV root 2>/dev/null
                ip link set dev $IFB_DEV down 2>/dev/null
                echo ">> 限速已取消。"
                ;;
            0)
                break
                ;;
            *)
                echo "无效选项。"
                ;;
        esac
    done
}

# 重装系统功能
reinstall_os() {
    echo "========== 系统重装工具 =========="
    echo -e "\033[33m警告: 重装系统将清除所有数据,请务必备份重要文件!\033[0m"
    echo ""
    
    # 选择下载源
    echo "请选择下载源:"
    echo "1. 国际源 (GitHub)"
    echo "2. 国内源 (Gitee)"
    echo "0. 返回"
    read -p "请选择 [1]: " source_choice
    source_choice=${source_choice:-1}
    
    case $source_choice in
        1)
            echo "使用国际源下载脚本..."
            SCRIPT_URL="https://raw.githubusercontent.com/leitbogioro/Tools/master/Linux_reinstall/InstallNET.sh"
            ;;
        2)
            echo "使用国内源下载脚本..."
            SCRIPT_URL="https://gitee.com/mb9e8j2/Tools/raw/master/Linux_reinstall/InstallNET.sh"
            ;;
        0)
            return 0
            ;;
        *)
            echo "无效选项,返回主菜单"
            return 1
            ;;
    esac
    
    # 下载重装脚本
    echo "正在下载重装脚本..."
    wget --no-check-certificate -qO InstallNET.sh "$SCRIPT_URL"
    
    if [ ! -f "InstallNET.sh" ]; then
        echo -e "\033[31m× 脚本下载失败,请检查网络连接\033[0m"
        return 1
    fi
    
    chmod a+x InstallNET.sh
    echo -e "\033[32m✓ 脚本下载成功\033[0m"
    echo ""
    
    # 显示系统选择菜单
    while true; do
        echo "========== 选择要安装的系统 =========="
        echo "Linux 系统:"
        echo "  1. Debian (推荐: 稳定可靠)"
        echo "  2. Ubuntu"
        echo "  3. CentOS"
        echo "  4. AlmaLinux"
        echo "  5. RockyLinux"
        echo "  6. Fedora"
        echo "  7. Kali Linux"
        echo "  8. Alpine Linux (轻量级)"
        echo ""
        echo "Windows 系统:"
        echo "  9. Windows Server 2022"
        echo "  10. Windows Server 2019"
        echo "  11. Windows Server 2016"
        echo "  12. Windows Server 2012 R2"
        echo "  13. Windows 11 Pro"
        echo "  14. Windows 10 Enterprise LTSC"
        echo ""
        echo "  0. 返回"
        echo ""
        read -p "请选择系统 [1]: " os_choice
        os_choice=${os_choice:-1}
        
        case $os_choice in
            1)
                echo ""
                echo "Debian 版本选择:"
                echo "1. Debian 12 (最新稳定版,推荐)"
                echo "2. Debian 11"
                echo "3. Debian 10"
                read -p "请选择版本 [1]: " debian_ver
                debian_ver=${debian_ver:-1}
                case $debian_ver in
                    1) OS_CMD="bash InstallNET.sh -debian 12" ;;
                    2) OS_CMD="bash InstallNET.sh -debian 11" ;;
                    3) OS_CMD="bash InstallNET.sh -debian 10" ;;
                    *) echo "无效选项"; continue ;;
                esac
                ;;
            2)
                echo ""
                echo "Ubuntu 版本选择:"
                echo "1. Ubuntu 24.04 LTS (最新)"
                echo "2. Ubuntu 22.04 LTS"
                echo "3. Ubuntu 20.04 LTS"
                read -p "请选择版本 [2]: " ubuntu_ver
                ubuntu_ver=${ubuntu_ver:-2}
                case $ubuntu_ver in
                    1) OS_CMD="bash InstallNET.sh -ubuntu 24.04" ;;
                    2) OS_CMD="bash InstallNET.sh -ubuntu 22.04" ;;
                    3) OS_CMD="bash InstallNET.sh -ubuntu 20.04" ;;
                    *) echo "无效选项"; continue ;;
                esac
                ;;
            3)
                echo ""
                echo "CentOS 版本选择:"
                echo "1. CentOS 9 Stream"
                echo "2. CentOS 8 Stream"
                echo "3. CentOS 7"
                read -p "请选择版本 [1]: " centos_ver
                centos_ver=${centos_ver:-1}
                case $centos_ver in
                    1) OS_CMD="bash InstallNET.sh -centos 9-stream" ;;
                    2) OS_CMD="bash InstallNET.sh -centos 8-stream" ;;
                    3) OS_CMD="bash InstallNET.sh -centos 7" ;;
                    *) echo "无效选项"; continue ;;
                esac
                ;;
            4)
                echo ""
                echo "AlmaLinux 版本选择:"
                echo "1. AlmaLinux 9 (推荐)"
                echo "2. AlmaLinux 8"
                read -p "请选择版本 [1]: " alma_ver
                alma_ver=${alma_ver:-1}
                case $alma_ver in
                    1) OS_CMD="bash InstallNET.sh -almalinux 9" ;;
                    2) OS_CMD="bash InstallNET.sh -almalinux 8" ;;
                    *) echo "无效选项"; continue ;;
                esac
                ;;
            5)
                echo ""
                echo "RockyLinux 版本选择:"
                echo "1. RockyLinux 9 (推荐)"
                echo "2. RockyLinux 8"
                read -p "请选择版本 [1]: " rocky_ver
                rocky_ver=${rocky_ver:-1}
                case $rocky_ver in
                    1) OS_CMD="bash InstallNET.sh -rockylinux 9" ;;
                    2) OS_CMD="bash InstallNET.sh -rockylinux 8" ;;
                    *) echo "无效选项"; continue ;;
                esac
                ;;
            6)
                echo ""
                echo "Fedora 版本选择:"
                echo "1. Fedora 39"
                echo "2. Fedora 38"
                read -p "请选择版本 [1]: " fedora_ver
                fedora_ver=${fedora_ver:-1}
                case $fedora_ver in
                    1) OS_CMD="bash InstallNET.sh -fedora 39" ;;
                    2) OS_CMD="bash InstallNET.sh -fedora 38" ;;
                    *) echo "无效选项"; continue ;;
                esac
                ;;
            7)
                OS_CMD="bash InstallNET.sh -kali"
                ;;
            8)
                echo ""
                echo "Alpine Linux 版本选择:"
                echo "1. Alpine Edge (滚动更新,推荐)"
                echo "2. Alpine 3.18"
                echo "3. Alpine 3.17"
                read -p "请选择版本 [1]: " alpine_ver
                alpine_ver=${alpine_ver:-1}
                case $alpine_ver in
                    1) OS_CMD="bash InstallNET.sh -alpine edge" ;;
                    2) OS_CMD="bash InstallNET.sh -alpine 3.18" ;;
                    3) OS_CMD="bash InstallNET.sh -alpine 3.17" ;;
                    *) echo "无效选项"; continue ;;
                esac
                ;;
            9)
                OS_CMD="bash InstallNET.sh -windows 2022"
                ;;
            10)
                OS_CMD="bash InstallNET.sh -windows 2019"
                ;;
            11)
                OS_CMD="bash InstallNET.sh -windows 2016"
                ;;
            12)
                OS_CMD="bash InstallNET.sh -windows 2012"
                ;;
            13)
                OS_CMD="bash InstallNET.sh -windows 11"
                ;;
            14)
                OS_CMD="bash InstallNET.sh -windows 10"
                ;;
            0)
                echo "返回主菜单"
                return 0
                ;;
            *)
                echo "无效选项,请重新选择"
                continue
                ;;
        esac
        
        # 配置自定义选项
        echo ""
        echo "=========================================="
        echo "高级配置选项 (可选)"
        echo "=========================================="
        
        # 检查是否为Windows系统
        IS_WINDOWS=0
        if [[ "$OS_CMD" == *"-windows"* ]]; then
            IS_WINDOWS=1
        fi
        
        # 询问是否修改SSH端口 (Windows不支持)
        if [ $IS_WINDOWS -eq 0 ]; then
            read -p "是否需要自定义SSH端口? [y/N]: " custom_port
            if [[ "$custom_port" =~ ^([yY][eE][sS]|[yY])$ ]]; then
                while true; do
                    read -p "请输入SSH端口号 (1-65535) [默认22]: " ssh_port
                    ssh_port=${ssh_port:-22}
                    if [[ "$ssh_port" =~ ^[0-9]+$ ]] && [ "$ssh_port" -ge 1 ] && [ "$ssh_port" -le 65535 ]; then
                        OS_CMD="$OS_CMD -port \"$ssh_port\""
                        echo -e "\033[32m✓ SSH端口已设置为: $ssh_port\033[0m"
                        break
                    else
                        echo -e "\033[31m× 无效的端口号,请输入1-65535之间的数字\033[0m"
                    fi
                done
            else
                echo "使用默认SSH端口: 22"
            fi
        else
            echo -e "\033[33m注意: Windows系统不支持自定义SSH端口\033[0m"
        fi
        
        # 询问是否修改密码
        # 检查是否支持密码自定义
        SUPPORT_PWD=1
        if [[ "$OS_CMD" == *"-alpine"* ]] || [[ "$OS_CMD" == *"-ubuntu"* ]] || [[ "$OS_CMD" == *"-windows"* ]]; then
            SUPPORT_PWD=0
            echo -e "\033[33m注意: 该系统使用DD镜像安装方式,不支持自定义密码\033[0m"
            if [[ "$OS_CMD" == *"-windows"* ]]; then
                echo "  Windows系统默认密码: Teddysun.com"
                echo "  RDP端口: 3389"
            else
                echo "  默认密码: LeitboGi0ro"
            fi
        else
            read -p "是否需要自定义登录密码? [y/N]: " custom_pwd
            if [[ "$custom_pwd" =~ ^([yY][eE][sS]|[yY])$ ]]; then
                while true; do
                    read -s -p "请输入新密码: " new_password
                    echo ""
                    if [ -z "$new_password" ]; then
                        echo -e "\033[31m× 密码不能为空\033[0m"
                        continue
                    fi
                    # 检查密码中是否包含单引号
                    if [[ "$new_password" == *"'"* ]]; then
                        echo -e "\033[33m警告: 密码中包含单引号,将自动转义处理\033[0m"
                    fi
                    read -s -p "请再次输入密码确认: " new_password_confirm
                    echo ""
                    if [ "$new_password" = "$new_password_confirm" ]; then
                        # 转义密码中的单引号
                        escaped_password="${new_password//\'/\'\\\'\'}"
                        OS_CMD="$OS_CMD -pwd '$escaped_password'"
                        echo -e "\033[32m✓ 自定义密码已设置\033[0m"
                        break
                    else
                        echo -e "\033[31m× 两次输入的密码不一致,请重新输入\033[0m"
                    fi
                done
            else
                echo "使用默认密码: LeitboGi0ro"
            fi
        fi
        
        # 确认是否继续
        echo ""
        echo "=========================================="
        echo "最终配置信息:"
        echo "=========================================="
        
        # 显示系统信息
        if [[ "$OS_CMD" == *"-debian"* ]]; then
            echo "系统: Debian"
        elif [[ "$OS_CMD" == *"-ubuntu"* ]]; then
            echo "系统: Ubuntu (DD镜像安装)"
        elif [[ "$OS_CMD" == *"-centos"* ]]; then
            echo "系统: CentOS"
        elif [[ "$OS_CMD" == *"-almalinux"* ]]; then
            echo "系统: AlmaLinux"
        elif [[ "$OS_CMD" == *"-rockylinux"* ]]; then
            echo "系统: RockyLinux"
        elif [[ "$OS_CMD" == *"-fedora"* ]]; then
            echo "系统: Fedora"
        elif [[ "$OS_CMD" == *"-kali"* ]]; then
            echo "系统: Kali Linux"
        elif [[ "$OS_CMD" == *"-alpine"* ]]; then
            echo "系统: Alpine Linux (DD镜像安装)"
        elif [[ "$OS_CMD" == *"-windows"* ]]; then
            echo "系统: Windows (DD镜像安装)"
        fi
        
        # 显示端口信息
        if [ $IS_WINDOWS -eq 0 ]; then
            if [[ "$custom_port" =~ ^([yY][eE][sS]|[yY])$ ]]; then
                echo "SSH端口: $ssh_port (自定义)"
            else
                echo "SSH端口: 22 (默认)"
            fi
        else
            echo "RDP端口: 3389 (默认)"
        fi
        
        # 显示密码信息
        if [ $SUPPORT_PWD -eq 1 ]; then
            if [[ "$custom_pwd" =~ ^([yY][eE][sS]|[yY])$ ]]; then
                echo "登录密码: ******** (自定义)"
            else
                echo "登录密码: LeitboGi0ro (默认)"
            fi
        else
            if [[ "$OS_CMD" == *"-windows"* ]]; then
                echo "登录密码: Teddysun.com (默认,无法自定义)"
                echo "登录用户: Administrator"
            else
                echo "登录密码: LeitboGi0ro (默认,无法自定义)"
                echo "登录用户: root"
            fi
        fi
        
        echo ""
        echo "=========================================="
        echo -e "\033[33m即将执行命令:\033[0m"
        echo -e "\033[36m$OS_CMD\033[0m"
        echo "=========================================="
        echo -e "\033[31m警告: 此操作将会:"
        echo "  1. 清除当前系统的所有数据"
        echo "  2. 重新安装选定的操作系统"
        echo "  3. 过程中服务器将会重启"
        echo "  4. 安装过程可能需要10-40分钟\033[0m"
        echo ""
        
        read -p "确认要继续吗? 输入 YES 继续: " confirm
        
        if [ "$confirm" = "YES" ]; then
            echo ""
            echo "开始重装系统..."
            echo "请通过VNC或IPMI控制台查看安装进度"
            echo "安装过程可能需要10-40分钟,请耐心等待..."
            sleep 3
            eval $OS_CMD
            break
        else
            echo "已取消操作"
            return 0
        fi
    done
}

# 显示主菜单的函数
display_menu() {
    # 显示当前版本号
    get_version # 调用获取版本号函数
	echo "请选择一个选项:"
    echo "1. Network Tools"
    echo "2. Run Tests"
    echo "3. Other"
    echo "4. Reinstall OS"
    echo "5. Check Update"
    echo "0. Uninstall Script"
	
	# 恢复颜色为默认颜色
    echo -e "\e[39m"
}

# 显示network tools的二级菜单
display_network_tools_menu() {
    echo "1. install XrayR"
    echo "2. install Warp"
    echo "3. install Speedtest"
    echo "4. install network_optimize"
	echo "5. install Nxtrace"
	echo "6. install Realm"
	echo "7. install ddns"
    echo "0. return"
}

# 显示Run tests的二级菜单
display_run_tests_menu() {
    echo "1. Run NodeQuality"
    echo "0. 返回"
}

# 显示Other的二级菜单
display_other_menu() {
    echo "1. Add swap"
	echo "2. install bt panel"
	echo "3. install docker"
	echo "4. install python"
	echo "5. install ufw-docker"
	echo "6. Bandwidth Limit"
	echo "7. SSH Security Config"
    echo "0. 返回"
}

# 主程序,处理菜单选择
while true; do
    display_menu
    read -p "请选择一个选项:" choice
    case $choice in
        1)
            # 显示network tools 的二级菜单
            while true; do
                display_network_tools_menu
                read -p "请选择一个选项:" tools_choice
                case $tools_choice in
                    1) xrayr ;;  # 调用 XrayR 函数
                    2) warp ;;  # 调用 Warp 函数
                    3) speedtest ;;  # 调用 Speedtest 函数
                    4) network_optimize ;;  # 调用 network_optimize 函数
					5) nxtrace ;; #调用 nxtrace 函数
					6) realm ;; #调用 realm 函数
					7) ddns ;; #调用 ddns 函数
                    0) break ;;  # 返回上一层菜单
                    *) echo "无效选项。" ;;  # 输入无效选项的提示
                esac
            done
            ;;
        2)
            # 显示运行run test的二级菜单
            while true; do
                display_run_tests_menu
                read -p "请选择一个选项:" tests_choice
                case $tests_choice in
                    1) NodeQuality ;;  # 调用 NodeQuality 函数
                    0) break ;;  # 返回上一层菜单
                    *) echo "无效选项。" ;;  # 输入无效选项的提示
                esac
            done
            ;;
        3)
            # 显示other的二级菜单
            while true; do
                display_other_menu
                read -p "请选择一个选项:" other_choice
                case $other_choice in
                    1) swap ;;  # 调用 Swap 函数
					2) bt ;;  # 调用 bt 函数
					3) docker ;;  # 调用 docker 函数
					4) python ;; #调用 python 函数
					5) add_ufw_docker_rules ;;#调用 add_ufw_docker_rules 函数
					6) bandwidth_limit ;;#调用 带宽限制 函数
					7) ssh_security ;;#调用 SSH安全配置 函数
                    0) break ;;  # 返回上一层菜单
                    *) echo "无效选项。" ;;  # 输入无效选项的提示
                esac
            done
            ;;
        4) reinstall_os ;;  # 调用 reinstall_os 函数
        5) update ;;  # 调用 update 函数
        0) uninstall_script ;;  # 调用 uninstall_script 函数
        *) echo "无效选项,请重新选择。" ;;  # 输入无效选项的提示
    esac
done
