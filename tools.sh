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

    # 获取系统总内存(KB)
    total_mem=$(cat /proc/meminfo | grep MemTotal | awk '{print $2}')

    # 计算TCP内存参数 (基于总内存页数,假设4KB页)
    total_pages=$((total_mem / 4))
    t_min=$((total_pages / 4))
    t_avg=$((total_pages / 2))
    t_max=$total_pages

    # 确保最小值
    t_min=$((t_min < 98304 ? 98304 : t_min))
    t_avg=$((t_avg < 196608 ? 196608 : t_avg))
    t_max=$((t_max < 393216 ? 393216 : t_max))

    echo "系统总内存: $total_mem KB"

    # 选择优化策略
    echo "请选择优化策略:"
    echo "1. 临近策略 (香港/日本/新加坡等,低延迟)"
    echo "2. 远距离策略 (美国/加拿大等,高延迟)"
    read -p "请选择 [1]: " strategy
    strategy=${strategy:-1}

    case $strategy in
        2)
            echo "应用远距离优化参数..."
            rmem_max="67108864"   # 64MB
            wmem_max="67108864"   # 64MB
            backlog="131072"
            strategy_name="远距离优化"
            ;;
        *)
            echo "应用临近优化参数..."
            rmem_max="33554432"   # 32MB
            wmem_max="33554432"   # 32MB
            backlog="262144"
            strategy_name="临近优化"
            ;;
    esac

    # 准备sysctl参数
    declare -A params=(
        # IPv6启用和配置
        ["net.ipv6.conf.all.disable_ipv6"]="0"
        ["net.ipv6.conf.default.disable_ipv6"]="0"
        ["net.ipv6.conf.lo.disable_ipv6"]="0"
        ["net.ipv6.conf.all.forwarding"]="1"
        ["net.ipv6.conf.default.forwarding"]="1"
        ["net.ipv6.conf.all.accept_ra"]="2"
        ["net.ipv6.conf.default.accept_ra"]="2"
        ["net.ipv6.conf.all.accept_redirects"]="0"
        ["net.ipv6.conf.default.accept_redirects"]="0"
        ["net.ipv6.conf.all.autoconf"]="1"
        ["net.ipv6.conf.default.autoconf"]="1"

        # TCP拥塞控制 - BBR
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
        ["net.ipv4.tcp_no_metrics_save"]="0"

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
        ["net.ipv4.tcp_tw_reuse"]="1"
        ["net.ipv4.tcp_fin_timeout"]="30"

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

        # 延迟优化
        ["net.ipv4.tcp_keepalive_time"]="600"
        ["net.ipv4.tcp_keepalive_intvl"]="30"
        ["net.ipv4.tcp_keepalive_probes"]="5"

        # 虚拟内存
        ["vm.swappiness"]="10"
        ["vm.min_free_kbytes"]="4096"
    )

    # 备份原始配置
    if [ ! -f "/etc/sysctl.conf.bak" ]; then
        cp /etc/sysctl.conf /etc/sysctl.conf.bak
    fi

    # 应用sysctl参数
    for param in "${!params[@]}"; do
        value=${params[$param]}
        if grep -q "^$param" /etc/sysctl.conf; then
            sed -i "s|^$param.*|$param = $value|" /etc/sysctl.conf
        else
            echo "$param = $value" >> /etc/sysctl.conf
        fi
    done

    # 设置文件描述符限制
    if ! grep -q "nofile" /etc/security/limits.conf; then
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
    sysctl -p > /dev/null 2>&1

    # 显示优化摘要
    echo ""
    echo "========================================="
    echo "           优化摘要"
    echo "========================================="
    echo "优化策略: $strategy_name"
    echo "系统内存: $(awk "BEGIN {printf \"%.2f GB\", $total_mem/1024/1024}")"
    echo "-----------------------------------------"
    echo "缓冲区配置:"
    echo "  接收缓冲: $(awk "BEGIN {printf \"%.0f MB\", $rmem_max/1024/1024}")"
    echo "  发送缓冲: $(awk "BEGIN {printf \"%.0f MB\", $wmem_max/1024/1024}")"
    echo "  连接队列: $backlog"
    echo "-----------------------------------------"
    echo "网络协议:"
    echo "  IPv4转发: $(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo '未知')"
    echo "  IPv6转发: $(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null || echo '未知')"
    echo "  IPv6状态: 已启用"
    echo "-----------------------------------------"
    echo "TCP优化:"
    echo "  拥塞控制: $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo '未知')"
    echo "  队列算法: $(sysctl -n net.core.default_qdisc 2>/dev/null || echo '未知')"
    echo "  Fast Open: $(sysctl -n net.ipv4.tcp_fastopen 2>/dev/null || echo '未知')"
    echo "-----------------------------------------"
    echo "系统限制:"
    echo "  文件描述符: 1048576"
    echo "  最大进程数: 1048576"
    echo "  最大PID: $(sysctl -n kernel.pid_max 2>/dev/null || echo '未知')"
    echo "========================================="
    echo "网络优化完成! 建议重启系统以确保所有配置生效"
    echo "========================================="
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
#!/bin/bash

ssh_security() {
    echo "========== SSH安全配置 =========="
    echo "此功能将会:"
    echo "1. 禁用SSH密码登录"
    echo "2. 启用SSH密钥登录"
    echo "3. 检查并处理所有可能覆盖配置的文件"
    echo ""
    echo -e "\033[31m警告: 在继续之前,请确保您已经设置了SSH密钥!\033[0m"
    echo -e "\033[31m如果没有密钥,您可能会失去服务器访问权限!\033[0m"
    echo ""
    
    # 检查是否已存在授权密钥
    # 不仅检查文件是否存在，还要检查是否有有效的密钥
    has_valid_key=false
    
    if [ -f ~/.ssh/authorized_keys ]; then
        # 检查是否有有效的公钥（以ssh-开头或ecdsa-开头的非注释行）
        if grep -qE "^(ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-)" ~/.ssh/authorized_keys 2>/dev/null; then
            has_valid_key=true
            key_count=$(grep -cE "^(ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-)" ~/.ssh/authorized_keys 2>/dev/null)
            echo -e "\033[32m✓ 检测到已存在 $key_count 个SSH密钥\033[0m"
        fi
    fi
    
    if [ "$has_valid_key" = false ]; then
        echo -e "\033[33m检测到您还没有设置SSH密钥。\033[0m"
        
        # 如果文件存在但没有有效密钥，显示文件内容供参考
        if [ -f ~/.ssh/authorized_keys ] && [ -s ~/.ssh/authorized_keys ]; then
            echo -e "\033[33m当前 authorized_keys 文件内容：\033[0m"
            cat ~/.ssh/authorized_keys | head -5
            echo ""
        fi
        
        read -p "是否现在添加SSH公钥?[Y/n]: " add_key_response
        add_key_response=${add_key_response:-Y}
        
        if [[ "$add_key_response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
            # 创建.ssh目录
            mkdir -p ~/.ssh
            chmod 700 ~/.ssh
            
            echo "请输入您的SSH公钥内容(通常以ssh-rsa、ssh-ed25519等开头):"
            read -r ssh_public_key
            
            if [ -n "$ssh_public_key" ]; then
                # 验证公钥格式
                if [[ "$ssh_public_key" =~ ^(ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-) ]]; then
                    echo "$ssh_public_key" >> ~/.ssh/authorized_keys
                    chmod 600 ~/.ssh/authorized_keys
                    echo -e "\033[32m✓ SSH公钥已添加到authorized_keys\033[0m"
                else
                    echo -e "\033[31m× 公钥格式无效（应以ssh-rsa、ssh-ed25519等开头）,操作取消\033[0m"
                    return 1
                fi
            else
                echo -e "\033[31m× 未输入有效的公钥,操作取消\033[0m"
                return 1
            fi
        else
            echo -e "\033[31m× 没有SSH密钥的情况下禁用密码登录是危险的,操作取消\033[0m"
            return 1
        fi
    fi
    
    # 检测所有可能的SSH配置文件
    echo ""
    echo "========== 检测SSH配置文件 =========="
    
    SSH_MAIN_CONFIG="/etc/ssh/sshd_config"
    SSH_CONFIG_DIR="/etc/ssh/sshd_config.d"
    
    # 存储所有需要处理的配置文件
    declare -a CONFIG_FILES=("$SSH_MAIN_CONFIG")
    
    # 检查主配置文件是否包含Include指令
    if [ -f "$SSH_MAIN_CONFIG" ]; then
        echo "检查主配置文件: $SSH_MAIN_CONFIG"
        
        # 查找所有Include指令
        while IFS= read -r include_line; do
            # 移除注释和前导空格
            include_path=$(echo "$include_line" | sed 's/^[[:space:]]*Include[[:space:]]*//' | sed 's/[[:space:]]*$//')
            
            # 处理通配符
            if [[ "$include_path" == /* ]]; then
                # 绝对路径
                for file in $include_path; do
                    if [ -f "$file" ]; then
                        CONFIG_FILES+=("$file")
                        echo "  发现Include文件: $file"
                    fi
                done
            else
                # 相对路径，相对于/etc/ssh
                for file in /etc/ssh/$include_path; do
                    if [ -f "$file" ]; then
                        CONFIG_FILES+=("$file")
                        echo "  发现Include文件: $file"
                    fi
                done
            fi
        done < <(grep -i "^[[:space:]]*Include" "$SSH_MAIN_CONFIG" 2>/dev/null)
    fi
    
    # 检查默认的sshd_config.d目录
    if [ -d "$SSH_CONFIG_DIR" ]; then
        echo "检查配置目录: $SSH_CONFIG_DIR"
        while IFS= read -r -d '' file; do
            # 只处理.conf文件
            if [[ "$file" == *.conf ]]; then
                CONFIG_FILES+=("$file")
                echo "  发现配置文件: $file"
            fi
        done < <(find "$SSH_CONFIG_DIR" -type f -print0 2>/dev/null)
    fi
    
    # 检查云服务商特定配置（常见的会覆盖配置的文件）
    CLOUD_CONFIGS=(
        "/etc/ssh/sshd_config.d/50-cloud-init.conf"
        "/etc/ssh/sshd_config.d/60-cloudimg-settings.conf"
        "/etc/ssh/sshd_config.d/50-cloudimg-settings.conf"
        "/etc/ssh/ssh_config.d/50-cloud-init.conf"
    )
    
    for cloud_config in "${CLOUD_CONFIGS[@]}"; do
        if [ -f "$cloud_config" ] && [[ ! " ${CONFIG_FILES[@]} " =~ " ${cloud_config} " ]]; then
            CONFIG_FILES+=("$cloud_config")
            echo "  发现云服务商配置: $cloud_config"
        fi
    done
    
    echo ""
    echo "共发现 ${#CONFIG_FILES[@]} 个配置文件需要处理"
    
    # 显示当前相关配置状态
    echo ""
    echo "========== 当前配置状态 =========="
    for config_file in "${CONFIG_FILES[@]}"; do
        if [ -f "$config_file" ]; then
            echo "文件: $config_file"
            
            # 检查PasswordAuthentication设置
            pass_auth=$(grep -i "^[[:space:]]*PasswordAuthentication" "$config_file" 2>/dev/null | tail -1)
            if [ -n "$pass_auth" ]; then
                echo "  PasswordAuthentication: $pass_auth"
            fi
            
            # 检查PubkeyAuthentication设置
            pubkey_auth=$(grep -i "^[[:space:]]*PubkeyAuthentication" "$config_file" 2>/dev/null | tail -1)
            if [ -n "$pubkey_auth" ]; then
                echo "  PubkeyAuthentication: $pubkey_auth"
            fi
            
            # 检查ChallengeResponseAuthentication
            challenge_auth=$(grep -i "^[[:space:]]*ChallengeResponseAuthentication" "$config_file" 2>/dev/null | tail -1)
            if [ -n "$challenge_auth" ]; then
                echo "  ChallengeResponseAuthentication: $challenge_auth"
            fi
            
            # 检查UsePAM
            use_pam=$(grep -i "^[[:space:]]*UsePAM" "$config_file" 2>/dev/null | tail -1)
            if [ -n "$use_pam" ]; then
                echo "  UsePAM: $use_pam"
            fi
            
            # 检查KbdInteractiveAuthentication (新版本SSH)
            kbd_auth=$(grep -i "^[[:space:]]*KbdInteractiveAuthentication" "$config_file" 2>/dev/null | tail -1)
            if [ -n "$kbd_auth" ]; then
                echo "  KbdInteractiveAuthentication: $kbd_auth"
            fi
            
            echo ""
        fi
    done
    
    # 最终确认
    echo "即将进行以下配置:"
    echo "- 禁用密码登录"
    echo "- 启用公钥认证"
    echo "- 禁用挑战响应认证"
    echo "- 禁用键盘交互认证"
    echo "- 处理所有检测到的配置文件"
    echo ""
    read -p "确认继续?[y/N]: " final_confirm
    
    if [[ ! "$final_confirm" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        echo "操作取消"
        return 0
    fi
    
    # 备份所有配置文件
    echo ""
    echo "========== 备份配置文件 =========="
    BACKUP_DIR="/etc/ssh/backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    
    for config_file in "${CONFIG_FILES[@]}"; do
        if [ -f "$config_file" ]; then
            backup_file="$BACKUP_DIR/$(basename $config_file)"
            cp "$config_file" "$backup_file"
            echo "已备份: $config_file -> $backup_file"
        fi
    done
    
    # 应用安全配置的函数
    apply_security_config() {
        local file=$1
        local tmpfile=$(mktemp)
        
        # 复制原文件到临时文件
        cp "$file" "$tmpfile"
        
        # 注释掉或删除现有的相关配置
        sed -i 's/^[[:space:]]*PasswordAuthentication.*/#&/' "$tmpfile"
        sed -i 's/^[[:space:]]*PubkeyAuthentication.*/#&/' "$tmpfile"
        sed -i 's/^[[:space:]]*ChallengeResponseAuthentication.*/#&/' "$tmpfile"
        sed -i 's/^[[:space:]]*KbdInteractiveAuthentication.*/#&/' "$tmpfile"
        
        # 在文件末尾添加安全配置
        cat >> "$tmpfile" << EOF

# Security configuration applied on $(date)
# Added by ssh_security() function
PasswordAuthentication no
PubkeyAuthentication yes
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
EOF
        
        # 替换原文件
        mv "$tmpfile" "$file"
    }
    
    # 应用配置到所有文件
    echo ""
    echo "========== 应用安全配置 =========="
    for config_file in "${CONFIG_FILES[@]}"; do
        if [ -f "$config_file" ]; then
            echo "处理: $config_file"
            apply_security_config "$config_file"
            echo -e "\033[32m✓ 已配置\033[0m"
        fi
    done
    
    # 特殊处理：禁用cloud-init的SSH配置重置
    CLOUD_INIT_CONFIG="/etc/cloud/cloud.cfg"
    if [ -f "$CLOUD_INIT_CONFIG" ]; then
        echo ""
        echo "检测到cloud-init配置文件"
        if grep -q "ssh_pwauth" "$CLOUD_INIT_CONFIG" 2>/dev/null; then
            read -p "是否禁用cloud-init的SSH密码认证管理?[Y/n]: " disable_cloud_init
            disable_cloud_init=${disable_cloud_init:-Y}
            
            if [[ "$disable_cloud_init" =~ ^([yY][eE][sS]|[yY])$ ]]; then
                cp "$CLOUD_INIT_CONFIG" "$BACKUP_DIR/cloud.cfg"
                sed -i 's/^ssh_pwauth:.*$/ssh_pwauth: false/' "$CLOUD_INIT_CONFIG"
                echo -e "\033[32m✓ 已禁用cloud-init的SSH密码认证\033[0m"
            fi
        fi
    fi
    
    # 测试SSH配置
    echo ""
    echo "========== 测试配置 =========="
    echo "测试SSH配置语法..."
    if sshd -t 2>/dev/null; then
        echo -e "\033[32m✓ SSH配置语法正确\033[0m"
        
        # 显示最终生效的配置
        echo ""
        echo "========== 验证最终配置 =========="
        echo "检查sshd实际会使用的配置:"
        sshd -T 2>/dev/null | grep -E "^(passwordauthentication|pubkeyauthentication|challengeresponseauthentication|kbdinteractiveauthentication)" | while read line; do
            if [[ "$line" =~ "yes" && "$line" =~ "password" ]]; then
                echo -e "\033[33m  $line\033[0m"
            elif [[ "$line" =~ "no" && "$line" =~ "pubkey" ]]; then
                echo -e "\033[33m  $line\033[0m"
            else
                echo "  $line"
            fi
        done
        
        echo ""
        read -p "配置看起来正确吗？是否重启SSH服务?[Y/n]: " restart_confirm
        restart_confirm=${restart_confirm:-Y}
        
        if [[ "$restart_confirm" =~ ^([yY][eE][sS]|[yY])$ ]]; then
            # 重启SSH服务
            echo "重启SSH服务..."
            systemctl restart sshd
            
            if systemctl is-active --quiet sshd; then
                echo -e "\033[32m✓ SSH服务重启成功\033[0m"
                echo ""
                echo "========== 配置完成 =========="
                echo -e "\033[32m✓ SSH密码登录已禁用\033[0m"
                echo -e "\033[32m✓ SSH密钥登录已启用\033[0m"
                echo -e "\033[32m✓ 已处理所有配置文件\033[0m"
                echo ""
                echo "备份文件位置: $BACKUP_DIR"
                echo ""
                echo -e "\033[31m重要提醒:\033[0m"
                echo "1. 请不要关闭当前SSH连接"
                echo "2. 请在新终端中测试SSH密钥登录"
                echo "3. 确认可以正常登录后再关闭当前会话"
                echo "4. 如需回滚，可从 $BACKUP_DIR 恢复配置"
                echo ""
                echo "回滚命令:"
                for config_file in "${CONFIG_FILES[@]}"; do
                    if [ -f "$config_file" ]; then
                        echo "  cp $BACKUP_DIR/$(basename $config_file) $config_file"
                    fi
                done
                echo "  systemctl restart sshd"
            else
                echo -e "\033[31m× SSH服务重启失败\033[0m"
                echo "正在恢复配置..."
                for config_file in "${CONFIG_FILES[@]}"; do
                    if [ -f "$BACKUP_DIR/$(basename $config_file)" ]; then
                        cp "$BACKUP_DIR/$(basename $config_file)" "$config_file"
                    fi
                done
                systemctl restart sshd
                echo "已恢复原始配置"
            fi
        else
            echo "已取消重启SSH服务"
            echo "您可以稍后手动执行: systemctl restart sshd"
        fi
    else
        echo -e "\033[31m× SSH配置语法错误\033[0m"
        sshd -t
        echo ""
        echo "正在恢复配置..."
        for config_file in "${CONFIG_FILES[@]}"; do
            if [ -f "$BACKUP_DIR/$(basename $config_file)" ]; then
                cp "$BACKUP_DIR/$(basename $config_file)" "$config_file"
            fi
        done
        echo "已恢复原始配置"
        return 1
    fi
}

# 如果直接运行此脚本（而不是source），则执行函数
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    ssh_security
fi

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
# 重装系统功能
reinstall_os() {
    echo -e "${green}========== 系统重装工具 ==========${plain}"
    echo -e "${yellow}警告: 重装系统将清除所有数据,请务必备份重要文件!${plain}"
    echo ""
    
    # 检查root权限
    if [ "$EUID" -ne 0 ]; then
        echo -e "${red}错误: 此功能需要root权限运行${plain}"
        return 1
    fi
    
    # 选择下载源
    echo "请选择下载源:"
    echo "1. 国际源 (GitHub)"
    echo "2. 国内源 (cnb.cool)"
    echo "0. 返回"
    read -p "请选择 [1]: " source_choice
    source_choice=${source_choice:-1}
    
    case $source_choice in
        1)
            echo "使用国际源..."
            SCRIPT_URL="https://raw.githubusercontent.com/bin456789/reinstall/main/reinstall.sh"
            ;;
        2)
            echo "使用国内源..."
            SCRIPT_URL="https://cnb.cool/bin456789/reinstall/-/git/raw/main/reinstall.sh"
            ;;
        0)
            return 0
            ;;
        *)
            echo -e "${red}无效选项${plain}"
            return 1
            ;;
    esac
    
    # 下载重装脚本
    echo "正在下载重装脚本..."
    wget --no-check-certificate -O reinstall.sh "$SCRIPT_URL" 2>/dev/null || \
    curl -LsO "$SCRIPT_URL" 2>/dev/null
    
    if [ ! -f "reinstall.sh" ] || [ ! -s "reinstall.sh" ]; then
        echo -e "${red}× 脚本下载失败,请检查网络连接${plain}"
        return 1
    fi
    
    chmod a+x reinstall.sh
    echo -e "${green}✓ 脚本下载成功${plain}"
    echo ""
    
    # 选择系统
    echo "请选择系统:"
    echo "1. Debian"
    echo "2. Ubuntu"
    echo "0. 返回"
    read -p "请选择 [1]: " os_choice
    os_choice=${os_choice:-1}
    
    case $os_choice in
        1)
            echo ""
            echo "请选择Debian版本:"
            echo "1. Debian 13"
            echo "2. Debian 12"
            echo "3. Debian 11"
            read -p "请选择版本 [2]: " debian_ver
            debian_ver=${debian_ver:-2}
            case $debian_ver in
                1) OS_NAME="debian" && OS_VER="13" ;;
                2) OS_NAME="debian" && OS_VER="12" ;;
                3) OS_NAME="debian" && OS_VER="11" ;;
                *) echo "无效选项"; return 1 ;;
            esac
            ;;
        2)
            echo ""
            echo "请选择Ubuntu版本:"
            echo "1. Ubuntu 24.04"
            echo "2. Ubuntu 22.04"
            echo "3. Ubuntu 20.04"
            read -p "请选择版本 [1]: " ubuntu_ver
            ubuntu_ver=${ubuntu_ver:-1}
            case $ubuntu_ver in
                1) OS_NAME="ubuntu" && OS_VER="24.04" ;;
                2) OS_NAME="ubuntu" && OS_VER="22.04" ;;
                3) OS_NAME="ubuntu" && OS_VER="20.04" ;;
                *) echo "无效选项"; return 1 ;;
            esac
            ;;
        0)
            return 0
            ;;
        *)
            echo -e "${red}无效选项${plain}"
            return 1
            ;;
    esac
    
    # 输入密码
    echo ""
    while true; do
        read -p "请输入root密码: " password
        echo ""
        if [ -z "$password" ]; then
            echo -e "${red}× 密码不能为空${plain}"
            continue
        fi
        read -p "请再次输入密码确认: " password_confirm
        echo ""
        if [ "$password" = "$password_confirm" ]; then
            break
        else
            echo -e "${red}× 两次输入的密码不一致,请重新输入${plain}"
        fi
    done
    
    # 显示最终命令
    echo ""
    echo "=========================================="
    echo "即将执行:"
    echo -e "${cyan}./reinstall.sh $OS_NAME $OS_VER --password xxxx${plain}"
    echo ""
    echo -e "${red}警告: 此操作将会清除所有数据并重启服务器${plain}"
    echo ""
    
    read -p "确认要继续吗? 输入 YES 继续: " confirm
    
    if [[ "$confirm" =~ ^[yY][eE][sS]$ ]] || [[ "$confirm" =~ ^[yY]$ ]]; then
        echo ""
        echo "开始重装系统..."
        echo "请通过VNC查看安装进度"
        sleep 2
        ./reinstall.sh "$OS_NAME" "$OS_VER" --password "$password"
        exit 0
    else
        echo "已取消操作"
    fi
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
