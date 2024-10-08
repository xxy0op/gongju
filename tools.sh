#!/bin/bash

# ANSI Color Codes
green='\033[0;32m'
plain='\033[0m'

# Display Banner in Green
echo -e "${green}     _  _             _  _            _  _  _  ${plain}"
echo -e "${green}  _ (_)(_) _       _ (_)(_) _      _ (_)(_)(_) _  ${plain}"
echo -e "${green} (_)      (_)     (_)      (_)    (_)         (_) ${plain}"
echo -e "${green}(_)        (_)   (_)        (_)             _ (_) ${plain}"
echo -e "${green}(_)        (_)   (_)        (_)          _ (_)    ${plain}"
echo -e "${green}(_)        (_)   (_)        (_)       _ (_)       ${plain}"
echo -e "${green} (_) _  _ (_)     (_) _  _ (_)     _ (_) _  _  _  ${plain}"
echo -e "${green}    (_)(_)           (_)(_)       (_)(_)(_)(_)(_) ${plain}"




# 版本号
VERSION="1.6.8"

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
check_update() {
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
install_xrayr() {
    echo "正在安装 XrayR 脚本..."
    # 执行 XrayR 安装脚本
    bash <(curl -Ls https://raw.githubusercontent.com/XrayR-project/XrayR-release/master/install.sh) 0.9.0
}

# 运行融合怪测评脚本
run_fusion_script() {
    echo "运行融合怪测评脚本..."
    # 下载并执行融合怪测评脚本
    bash <(wget -qO- --no-check-certificate https://gitlab.com/spiritysdx/za/-/raw/main/ecs.sh)
}

# 安装 nxtrace 脚本
nxtrace() {
    echo "正在安装 nxtrace 脚本..."
    # 使用 curl 下载 nt 脚本并执行
    curl nxtrace.org/nt | bash
}

# 安装 Warp 脚本
install_warp() {
    echo "正在安装 Warp 脚本..."
    # 下载并执行 Warp 安装脚本
    wget -N https://gitlab.com/fscarmen/warp/-/raw/main/menu.sh && bash menu.sh
}

# 运行 流媒体测试 脚本
run_streaming_test() {
    echo "运行流媒体测试脚本..."
    # 执行流媒体测试脚本
    bash <(curl -L -s media.ispvps.com)
}

# 安装 speedtest 脚本
install_speedtest() {
    echo "正在安装 speedtest 脚本..."
    # 安装 curl
    sudo apt-get install -y curl
    # 安装 speedtest-cli
    curl -s https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh | sudo bash
    sudo apt-get install -y speedtest
}

# 安装Yeah脚本
install_yeah() {
    echo "正在安装 yeah 脚本..."
    # 准备sysctl参数
    declare -A params=(
        ["net.ipv4.ip_forward"]="1"
        ["net.ipv4.tcp_window_scaling"]="1"
        ["net.ipv4.tcp_adv_win_scale"]="-1"
        ["net.ipv4.tcp_timestamps"]="1"
        ["net.ipv4.tcp_no_metrics_save"]="1"
        ["net.ipv4.conf.default.rp_filter"]="1"
        ["net.ipv4.conf.all.rp_filter"]="1"
        ["net.ipv4.conf.default.accept_source_route"]="0"
        ["net.ipv4.tcp_rmem"]="8192 87380 33554432"
        ["net.ipv4.tcp_wmem"]="4096 16384 33554432"
        ["net.ipv4.udp_rmem_min"]="4096"
        ["net.ipv4.udp_wmem_min"]="4096"
        ["net.core.default_qdisc"]="fq"
        ["net.ipv4.tcp_congestion_control"]="yeah"
        ["kernel.pid_max"]="4194304"
        ["fs.file-max"]="2097152"
        ["fs.protected_hardlinks"]="1"
        ["fs.protected_symlinks"]="1"
        ["vm.compaction_proactiveness"]="0"
        ["vm.extfrag_threshold"]="1000"
        ["kernel.core_uses_pid"]="1"
		["net.ipv6.conf.all.disable_ipv6"]="1"
		["net.ipv6.conf.default.disable_ipv6"]="1"
		["net.ipv6.conf.lo.disable_ipv6"]="1"
    )

    # 应用 sysctl 参数
    echo "Applying sysctl parameters..."
    for param in "${!params[@]}"; do
        value=${params[$param]}
        if grep -q "^$param" /etc/sysctl.conf; then
            # 如果存在，则使用sed命令更新其值
            sed -i "s/^$param.*/$param = $value/" /etc/sysctl.conf
        else
            # 如果不存在，则追加到文件末尾
            echo "$param = $value" >> /etc/sysctl.conf
        fi
    done

    # 应用所有 sysctl 参数
    sysctl --system

    # 询问是否需要重启
    read -p "安装完成，是否需要重启服务器？[Y/n]" restart_response
    if [[ "$restart_response" =~ ^([yY][eE][sS]|[yY])+$ ]]; then
        echo "正在重启服务器..."
        reboot
    else
        echo "未选择重启服务器，脚本将继续运行。"
    fi
}


# 安装 dd_alpine 脚本
install_dd_alpine() {
    echo "正在安装 dd_alpine 脚本..."
    # 在这里添加运行 dd_alpine 脚本的命令
    # 示例：下载并执行另一个脚本
    wget https://www.moerats.com/usr/shell/alpine.sh && \
    bash alpine.sh
}

# 安装 Alpine XrayR 脚本
install_alpine_xrayr() {
    echo "正在安装 Alpine XrayR 脚本..."
    # 下载 Alpine XrayR 安装脚本
    wget https://github.com/Cd1s/alpineXrayR/releases/download/one-click/install-xrayr.sh && \
    # 添加执行权限
    chmod +x install-xrayr.sh && \
    # 执行安装脚本
    bash install-xrayr.sh
}

# 安装 宝塔6.0 脚本
install_bt6() {
    echo "正在安装宝塔6.0脚本..."
    # 下载并执行宝塔6.0安装脚本
    wget -O install.sh http://www.aapanel.com/script/install-ubuntu_6.0_en.sh && sudo bash install.sh
}

# 添加swap分区函数
add_swap_partition() {
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

# 下载并运行Cloudflare DDNS脚本
download_and_run_cloudflare_ddns() {
    echo "正在下载并运行 Cloudflare DDNS 脚本..."
    # 下载 Cloudflare DDNS 脚本
    wget -O /root/cloudflareddns.sh https://raw.githubusercontent.com/xxy0op/cloudflareddns/main/cloudflareddns.sh
    # 添加执行权限
    chmod +x /root/cloudflareddns.sh
    # 执行 Cloudflare DDNS 脚本
    /root/cloudflareddns.sh
}

# 显示菜单函数
display_menu() {
    # 显示当前版本号
    get_version # 调用获取版本号函数
    echo "请选择一个选项："
    echo "1. 安装 XrayR 脚本"
    echo "2. 运行融合怪测评脚本"
    echo "3. 安装 nxtrace 脚本"
    echo "4. 安装 Warp 脚本"
    echo "5. 运行 流媒体测试 脚本"
    echo "6. 安装 宝塔6.0 脚本"
    echo "7. 安装 speedtest 脚本"
    echo "8. 安装 yeah 脚本"
    echo "9. 安装 dd_alpine 脚本"
    echo "10. 安装 Alpine XrayR 脚本"
	echo "11. 添加swap分区"
	echo "12. 检查更新"  # 添加检查更新选项
	echo "13. 下载并运行 Cloudflare DDNS 脚本"  # 新增下载并运行 Cloudflare DDNS 脚本选项
    echo "0. 卸载脚本"  # 修改卸载脚本选项
	
	# 恢复颜色为默认颜色
    echo -e "\e[39m"
}

# 主脚本
while true; do
    display_menu
    read -p "请输入您的选择（0-10）：" choice
    case $choice in
        0) uninstall_script ;;   # 对于选项 0，调用 uninstall_script 函数
        1) install_xrayr ;;   # 对于选项 1，调用 install_xrayr 函数
        2) run_fusion_script ;;   # 对于选项 2，调用 run_fusion_script 函数
        3) nxtrace ;;   # 对于选项 3，调用 nxtrace 函数
        4) install_warp ;;   # 对于选项 4，调用 install_warp 函数
        5) run_streaming_test ;;   # 对于选项 5，调用 run_streaming_test 函数
        6) install_bt6 ;;   # 对于选项 6，调用 install_bt6 函数
        7) install_speedtest ;;   # 对于选项 7，调用 install_speedtest 函数
        8) install_yeah ;;   # 对于选项 8，调用 install_yeah 函数
        9) install_dd_alpine ;;   # 对于选项 9，调用 install_dd_alpine 函数
        10) install_alpine_xrayr ;;   # 对于选项 10，调用 install_alpine_xrayr 函数
		11) add_swap_partition ;;   # 对于选项 11，调用 add_swap_partition 函数
		12) check_update ;;  # 对于选项 12，调用 check_update 函数
		13) download_and_run_cloudflare_ddns ;;   # 对于选项 13，调用 download_and_run_cloudflare_ddns 函数
        *) echo -e "\e[33m退出脚本,请输入有效选择...\e[39m"; exit ;;   # 对于无效选择，退出脚本
    esac
done  