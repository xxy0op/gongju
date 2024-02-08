#!/bin/bash

# 安装 XrayR 脚本
install_xrayr() {
    echo "正在安装 XrayR 脚本..."
    # 执行 XrayR 安装脚本
    bash <(curl -Ls https://raw.githubusercontent.com/XrayR-project/XrayR-release/master/install.sh)
}

# 运行融合怪测评脚�?
run_fusion_script() {
    echo "运行融合怪测评脚�?.."
    # 下载并执行融合怪测评脚�?
    bash <(wget -qO- --no-check-certificate https://gitlab.com/spiritysdx/za/-/raw/main/ecs.sh)
}

# 安装 nxtrace 脚本
nxtrace() {
    echo "正在安装 nxtrace 脚本..."
    # 使用 curl 下载 nt 脚本并执�?
    curl nxtrace.org/nt | bash
}

# 安装 Warp 脚本
install_warp() {
    echo "正在安装 Warp 脚本..."
    # 下载并执�?Warp 安装脚本
    wget -N https://gitlab.com/fscarmen/warp/-/raw/main/menu.sh && bash menu.sh
}

# 运行 流媒体测�?脚本
run_streaming_test() {
    echo "运行流媒体测试脚�?.."
    # 执行流媒体测试脚�?
    bash <(curl -L -s https://netflix.dad/detect-script)
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

# 安装 bbr 脚本
install_bbr() {
    echo "正在安装 bbr 脚本..."
    # 备份 sysctl.conf
    cp /etc/sysctl.conf /etc/sysctl.conf.bak
    # 执行 bbr 脚本
    bash <(curl -sL file.vip.ga/toolkit.sh) bbr1
}

# 安装 dd_alpine 脚本
install_dd_alpine() {
    echo "正在安装 dd_alpine 脚本..."
    # 在这里添加运�?dd_alpine 脚本的命�?
    # 示例：下载并执行另一个脚�?
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
    # 下载并执行宝�?.0安装脚本
    wget -O install.sh http://www.aapanel.com/script/install-ubuntu_6.0_en.sh && sudo bash install.sh
}

# 显示菜单函数
display_menu() {
    echo "请选择一个选项�?
    echo "1. 安装 XrayR 脚本"
    echo "2. 运行融合怪测评脚�?
    echo "3. 安装 nxtrace 脚本"
    echo "4. 安装 Warp 脚本"
    echo "5. 运行 流媒体测�?脚本"
    echo "6. 安装 宝塔6.0 脚本"
    echo "7. 安装 speedtest 脚本"
    echo "8. 安装 bbr 脚本"
    echo "9. 安装 dd_alpine 脚本"
    echo "10. 安装 Alpine XrayR 脚本"
}

# 主脚�?
while true; do
    display_menu
    read -p "请输入您的选择�?-10）：" choice
    case $choice in
        1) install_xrayr ;;   # 对于选项 1，调�?install_xrayr 函数
        2) run_fusion_script ;;   # 对于选项 2，调�?run_fusion_script 函数
        3) nxtrace ;;   # 对于选项 3，调�?nxtrace 函数
        4) install_warp ;;   # 对于选项 4，调�?install_warp 函数
        5) run_streaming_test ;;   # 对于选项 5，调�?run_streaming_test 函数
        6) install_bt6 ;;   # 对于选项 6，调�?install_bt6 函数
        7) install_speedtest ;;   # 对于选项 7，调�?install_speedtest 函数
        8) install_bbr ;;   # 对于选项 8，调�?install_bbr 函数
        9) install_dd_alpine ;;   # 对于选项 9，调�?install_dd_alpine 函数
        10) install_alpine_xrayr ;;   # 对于选项 10，调�?install_alpine_xrayr 函数
        *) echo "无效的选择。请输入 1 �?10 之间的数字�? ;;   # 对于无效选择，显示错误消�?
    esac
done

