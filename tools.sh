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
VERSION="1.1"	

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
            echo "发现新版本 $REMOTE_VERSION，是否更新？[Y/n]"
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
                    echo "更新完成，重新运行脚本..."
                    exec "/usr/local/bin/tools.sh" "$@"
                else
                    echo "下载新版本失败，无法更新。"
                fi
            fi
        else 
            echo "已经是最新版本。"
        fi
    else
        echo "无法获取远程版本信息，检查网络连接或稍后重试。"
    fi
}

# 卸载脚本函数
uninstall_script() {
    echo "确定要卸载脚本吗？ [默认n]:"
    read -r uninstall_response
    if [[ "$uninstall_response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        echo "卸载成功！"
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
    echo -e "\e[32m当前版本号：$VERSION\e[34m"
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


# 优化网络性能函数 - 新版整合
bbr() {
    echo "========== SS节点网络性能优化 =========="

    # 选择TCP拥塞控制算法
    echo "请选择TCP拥塞控制算法:"
    echo "1. BBR（推荐）"
    echo "2. YEAH"
    read -p "请选择 [1]: " algo_choice
    algo_choice=${algo_choice:-1}
    if [[ "$algo_choice" == "2" ]]; then
        CC_ALGO="yeah"
        echo "已选择 YEAH 算法"
    else
        CC_ALGO="bbr"
        echo "已选择 BBR 算法"
    fi

    modprobe tcp_$CC_ALGO
    echo "tcp_$CC_ALGO" | tee /etc/modules-load.d/bbr.conf

    [[ -z $(command -v ethtool) ]] && apt install ethtool -y

    rm -f /usr/lib/sysctl.d/50-default.conf \
          /usr/lib/sysctl.d/50-pid-max.conf \
          /usr/lib/sysctl.d/protect-links.conf \
          /etc/sysctl.d/99-*.conf \
          /usr/lib/sysctl.d/99-*.conf \
          /etc/sysctl.d/*.sysctl

    echo "" > /etc/sysctl.conf

    reservemem=$(($(lsmem -b | grep 'Total online memory' | awk '{print $4}') / 1048576 * 16))
    reserveminbytes=$((reservemem / 4))
    systemctl restart qdisconf 2>/dev/null

    t_size=$(($(awk '/MemTotal/ {print $2}' /proc/meminfo) * 1024))
    t_min=$((t_size / 4096 / 4))
    t_avg=$((t_size / 4096 / 8 * 3))
    t_max=$((t_size / 4096 / 4 * 2))
    t_min=$(( t_min < 4096 ? t_min : 4096 ))

    byte_mem_max=$(( $(lsmem -b | grep 'Total online' | awk '{print $4}') / 1048576 / 512 * 67108864 ))

    cat > /etc/sysctl.d/bbr.conf << EOF
net.ipv4.tcp_congestion_control = $CC_ALGO
net.core.default_qdisc = fq
net.ipv4.tcp_mem = ${t_min} ${t_avg} ${t_max}
net.ipv4.udp_mem = ${t_min} ${t_avg} ${t_max}
net.core.rmem_max = ${byte_mem_max}
net.core.wmem_max = ${byte_mem_max}
net.ipv4.tcp_rmem = 4096 $((${byte_mem_max}/4)) ${byte_mem_max}
net.ipv4.tcp_wmem = 4096 65536 ${byte_mem_max}
net.ipv4.tcp_collapse_max_bytes = $((${byte_mem_max}/8))
net.ipv4.tcp_notsent_lowat = 16384
net.core.busy_read = 50
net.core.busy_poll = 50
net.ipv4.tcp_ecn = 0
net.ipv4.ip_forward = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_moderate_rcvbuf = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_adv_win_scale = 1
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_thin_linear_timeouts = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.ip_local_port_range = 1024 65535
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF

    grep -q tcp_collapse_max_bytes /etc/sysctl.d/bbr.conf || sed -i '/tcp_collapse_max_bytes/d' /etc/sysctl.d/bbr.conf

    cat > /etc/sysctl.d/net_static.conf << EOF
net.core.netdev_budget = 1000
net.core.netdev_max_backlog = 10000
net.ipv4.tcp_max_orphans = 16384
net.core.somaxconn = 65536
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 20
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_fin_timeout = 5
net.ipv4.tcp_max_tw_buckets = 32768
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.conf.all.arp_ignore = 1
net.ipv4.conf.all.arp_announce = 2
EOF

    cat > /etc/sysctl.d/netfilter.conf << EOF
net.netfilter.nf_conntrack_buckets = 262144
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 10
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 10
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 10
net.netfilter.nf_conntrack_tcp_timeout_established = 600
net.netfilter.nf_conntrack_tcp_timeout_syn_recv = 5
net.netfilter.nf_conntrack_tcp_timeout_syn_sent = 5
net.netfilter.nf_conntrack_tcp_timeout_last_ack = 10
EOF

    cat > /etc/sysctl.d/fs_vm.conf << EOF
kernel.pid_max = 1048576
fs.file-max = 524288
vm.swappiness = 10
vm.min_free_kbytes = ${reserveminbytes}
vm.user_reserve_kbytes = ${reservemem}
vm.admin_reserve_kbytes = ${reservemem}
vm.compaction_proactiveness = 0
vm.nr_hugepages = 8
EOF

    echo "* soft nofile 1048576
* hard nofile 1048576
* soft nproc 1048576
* hard nproc 1048576
* soft core 1048576
* hard core 1048576
* hard memlock unlimited
* soft memlock unlimited" > /etc/security/limits.conf

    echo "vm.overcommit_memory=0
vm.vfs_cache_pressure=100
vm.dirty_background_ratio=10
vm.dirty_ratio=20
net.core.rmem_default=212992
net.core.wmem_default=212992
net.ipv4.tcp_shrink_window=0
net.ipv4.tcp_orphan_retries=0
net.ipv4.tcp_fastopen_blackhole_timeout_sec=0
net.core.optmem_max=131072
net.ipv4.udp_rmem_min=4096
net.ipv4.udp_wmem_min=4096
net.ipv4.tcp_probe_interval=600
net.ipv4.tcp_probe_threshold=8
net.ipv4.tcp_reordering=3
net.ipv4.tcp_frto=2
net.ipv4.tcp_tw_reuse=2
net.ipv4.tcp_tso_win_divisor=3
kernel.sched_autogroup_enabled=1
kernel.dmesg_restrict=1
net.ipv4.conf.default.send_redirects=1
net.ipv4.conf.all.send_redirects=1
net.ipv4.conf.default.accept_source_route=1
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.secure_redirects=1
net.ipv4.conf.all.secure_redirects=1
net.core.netdev_budget_usecs=8000
net.ipv4.conf.default.accept_redirects=1
net.ipv4.tcp_invalid_ratelimit=500
net.ipv4.tcp_syn_retries=6
net.ipv4.tcp_synack_retries=5
net.ipv4.tcp_retries1=3
net.ipv4.tcp_retries2=15
net.ipv4.tcp_sack=1
net.ipv4.tcp_dsack=1
net.ipv4.tcp_early_retrans=3
net.ipv4.tcp_syncookies=1
kernel.panic=0
fs.protected_hardlinks=0
fs.protected_symlinks=0
vm.extfrag_threshold=500
kernel.core_uses_pid=0
net.netfilter.nf_conntrack_udp_timeout=30
net.netfilter.nf_conntrack_udp_timeout_stream=120
net.netfilter.nf_flowtable_udp_timeout=30" > /etc/sysctl.d/revoke.conf

    echo never > /sys/kernel/mm/transparent_hugepage/defrag
    [[ ! -d /mnt/huge ]] && mkdir /mnt/huge && mount -t hugetlbfs none /mnt/huge
    grep -q "hugetlbfs" /etc/fstab || echo "none /mnt/huge hugetlbfs defaults 0 0" >> /etc/fstab
    command -v ifconfig >/dev/null || apt install net-tools -y

    sysctl -p && sysctl --system
    rm /etc/sysctl.d/revoke.conf
    clear
    echo -e "/etc/sysctl.conf 与 /etc/sysctl.d 下其他conf文件如有冲突项，请手动清理"
    echo -e "优化完成，建议立即重启系统。"
}


# 安装 nxtrace 脚本
nxtrace() {
    echo "正在安装 nxtrace 脚本..."
    # 使用 curl 下载 nt 脚本并执行
    curl nxtrace.org/nt | bash
}

#安装relam脚本
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

    # 获取用户输入的swap分区大小（单位：GB）
    read -p "请输入要创建的swap分区大小（单位：GB）：" swap_size_gb
    # 将GB转换为MB
    swap_size_mb=$((swap_size_gb * 1024))
    # 检查输入是否为正整数
    if ! [[ $swap_size_gb =~ ^[0-9]+$ ]]; then
        echo "错误：请输入一个正整数。"
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

#安装 docker
docker() {
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    rm get-docker.sh
    cleanlog
    docker_compose_install
    echo "已安装docker"
}

docker_compose_install() {
    local compose_version=$(curl -Ls "https://api.github.com/repos/docker/compose/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    [ -z "${compose_version}" ] && compose_version="v2.30.3"
	local compose_link=$(echo https://github.com/docker/compose/releases/download/${compose_version}/docker-compose-linux-$(arch))
    rm /usr/bin/docker-compose -f
    wget -qO /usr/bin/docker-compose ${compose_link}
    chmod +x /usr/bin/docker-compose
    rm /usr/libexec/docker/cli-plugins/docker-compose -f
    cp /usr/bin/docker-compose /usr/libexec/docker/cli-plugins/docker-compose
    echo "已安装docker-compose"
}

#安装 python
python() {
    apt install python3-full -y
    apt install python3-dev -y
    apt install python3-venv -y
    apt install pipx -y
    pipx ensurepath
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
        echo "UFW Docker 配置已存在，跳过添加。"
    else
        echo "$RULES" | sudo tee -a "$ufw_rules_file" > /dev/null
        echo "已成功添加规则，正在重启 UFW 服务..."
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
        read -p "请选择一个选项：" limit_choice
        case $limit_choice in
            1)
                read -p "请输入限速带宽（单位 Mbps，例如 200）: " RATE
                RATE="${RATE}mbit"

                echo ">> 正在配置限速，限速值: $RATE"

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

                echo ">> 限速配置完成，当前上下行限速 $RATE"
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



# 显示主菜单的函数
display_menu() {
    # 显示当前版本号
    get_version # 调用获取版本号函数
    echo "请选择一个选项："
    echo "1. Network Tools"
    echo "2. Run Tests"
    echo "3. Other"
    echo "4. Check Update"
    echo "0. Uninstall Script"
	
	# 恢复颜色为默认颜色
    echo -e "\e[39m"
}

# 显示network tools的二级菜单
display_network_tools_menu() {
echo "1. install XrayR"
echo "2. install Warp"
echo "3. install Speedtest"
echo "4. install bbr"
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
    echo "0. 返回"
}

# 主程序，处理菜单选择
while true; do
    display_menu
    read -p "请选择一个选项：" choice
    case $choice in
        1)
            # 显示network tools 的二级菜单
            while true; do
                display_network_tools_menu
                read -p "请选择一个选项：" tools_choice
                case $tools_choice in
                1) xrayr ;;  # 调用 XrayR 函数
        	2) warp ;;  # 调用 Warp 函数
                3) speedtest ;;  # 调用 Speedtest 函数
                4) bbr ;;  # 调用 bbr 函数
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
                read -p "请选择一个选项：" tests_choice
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
                read -p "请选择一个选项：" other_choice
                case $other_choice in
                1) swap ;;  # 调用 Swap 函数
		2) bt ;;  # 调用 bt 函数
		3) docker ;;  # 调用 docker 函数
		4) python ;; #调用 python 函数
		5) add_ufw_docker_rules ;;#调用 add_ufw_docker_rules 函数
		6) bandwidth_limit ;;#调用 带宽限制 函数
                0) break ;;  # 返回上一层菜单
                    *) echo "无效选项。" ;;  # 输入无效选项的提示
                esac
            done
            ;;
        4) update ;;  # 调用 update 函数
        0) uninstall_script ;;  # 调用 uninstall_script 函数
        *) echo "无效选项，请重新选择。" ;;  # 输入无效选项的提示
    esac
done
