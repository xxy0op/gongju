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
VERSION="2.0"

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

# 安装Yeah脚本
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
    
    # 计算保留内存
    reserve_mem=$(($total_mem / 16))
    reserve_min_bytes=$(($reserve_mem * 4))
    
    echo "系统总内存: $total_mem KB"
    echo "TCP内存参数: $t_min $t_avg $t_max"
    
    # 选择拥塞控制算法
    echo "请选择TCP拥塞控制算法:"
    echo "1. BBR (推荐, 适合大多数场景)"
    echo "2. YEAH (可能在某些特定网络环境有优势)"
    read -p "请选择 [1]: " algo_choice
    algo_choice=${algo_choice:-1}
    
    if [[ "$algo_choice" == "2" ]]; then
        CC_ALGO="yeah"
        echo "已选择 YEAH 算法"
    else
        CC_ALGO="bbr"
        echo "已选择 BBR 算法"
    fi
    
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
        # TCP拥塞控制
        ["net.ipv4.tcp_congestion_control"]="${CC_ALGO}"
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
        ["net.ipv6.conf.all.disable_ipv6"]="0"
        ["net.ipv6.conf.default.disable_ipv6"]="0"
        ["net.ipv6.conf.lo.disable_ipv6"]="0"
        
        # 延迟优化
        ["net.ipv4.tcp_keepalive_time"]="600"
        ["net.ipv4.tcp_keepalive_intvl"]="30"
        ["net.ipv4.tcp_keepalive_probes"]="10"
        ["net.ipv4.tcp_fin_timeout"]="30"
        
        # 虚拟内存
        ["vm.swappiness"]="10"
        ["vm.min_free_kbytes"]="${reserve_min_bytes}"
    )
    
    # 备份原始配置
    if [ ! -f "/etc/sysctl.conf.bak" ]; then
        echo "备份原始sysctl配置..."
        cp /etc/sysctl.conf /etc/sysctl.conf.bak
    fi
    
    # 应用sysctl参数
    echo "正在应用网络优化参数..."
    
    # 创建新的sysctl-ss.conf文件
    echo "# SS节点网络优化配置 - $(date)" > /etc/sysctl.d/99-ss-optimize.conf
    
    for param in "${!params[@]}"; do
        value=${params[$param]}
        echo "$param = $value" >> /etc/sysctl.d/99-ss-optimize.conf
        # 也更新主sysctl.conf文件
        if grep -q "^$param" /etc/sysctl.conf; then
            # 如果存在，则使用sed命令更新其值
            sed -i "s/^$param.*/$param = $value/" /etc/sysctl.conf
        else
            # 如果不存在，则追加到文件末尾
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
    sysctl --system
    
    if [ $? -eq 0 ]; then
        echo -e "\033[32m✓ 网络优化参数应用成功!\033[0m"
        echo "当前拥塞控制算法: $(sysctl -n net.ipv4.tcp_congestion_control)"
        echo "当前队列算法: $(sysctl -n net.core.default_qdisc)"
        echo "TCP Fast Open: $(sysctl -n net.ipv4.tcp_fastopen)"
    else
        echo -e "\033[31m× 部分参数应用失败，请检查日志\033[0m"
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

# 运行融合怪脚本
fusion() {
    echo "运行融合怪测评脚本..."
    # 下载并执行融合怪测评脚本
    bash <(wget -qO- --no-check-certificate https://gitlab.com/spiritysdx/za/-/raw/main/ecs.sh)
}

# 运行 流媒体测试 脚本
streaming() {
    echo "运行流媒体测试脚本..."
    # 执行流媒体测试脚本
    bash <(curl -L -s media.ispvps.com)
}

#运行ip check脚本
ipcheck() {
    bash <(curl -sL IP.Check.Place)
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
    echo "4. install network_optimize"
	echo "5. install Nxtrace"
	echo "6. install Realm"
	echo "7. install ddns"
    echo "0. return"
}

# 显示Run tests的二级菜单
display_run_tests_menu() {
    echo "1. Run Fusion"
    echo "2. Run streaming"
	echo "3. Run ipcheck"
    echo "0. 返回"
}

# 显示Other的二级菜单
display_other_menu() {
    echo "1. Add swap"
	echo "2. install bt panel"
	echo "3. install docker"
	echo "4. install python"
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
                read -p "请选择一个选项：" tests_choice
                case $tests_choice in
                    1) fusion ;;  # 调用 fusion 函数
                    2) streaming ;;  # 调用 streaming 函数
					3) ipcheck ;;  # 调用 ipcheck 函数
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