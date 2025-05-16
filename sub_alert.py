#!/usr/bin/env python3
#########################################################################
# 本脚本用于FileCoin日常巡检，及时告警通知到企业微信。
# 我们致力于提供开箱即用的Fil挖矿技术解决方案
# 如有问题联系脚本作者「mje」：
# WeChat：Mjy_Dream
#########################################################################

from __future__ import print_function
import time
import json
import re
import sys
import traceback
import subprocess as sp
from datetime import datetime, timedelta
import requests

# Server酱SendKey「必填，填写为自己的SendKey」
send_key = "SCT42628TJaSP3AraKD0Hua6u9evwVfft"
# 可配置Server酱推送到企业微信中特定人或多个人「选填，具体可参考文档」
openid = "MaJinYi"
# 脚本运行所在的机器类型
# lotus（一）、Seal-Miner（二）、Wining-Miner（三）、WindowPost-Miner（四）、存储机（五）
# 现做出约定，直接填写一、二、三、四来表示对应的机器类型，可写入多个类型
check_machine = "一"
# 机器别名，告警信息中进行展示，可以快速定位是哪台机器发出的告警信息
machine_name = "AI3_admin"
# 需要进行服务器宕机/网络不可达检验的内网ip，以|号分割
server_ip = "192.168.9.150|192.168.9.151|192.168.9.152|192.168.9.153|192.168.9.154|192.168.9.155|192.168.9.156|192.168.9.157|192.168.9.158|192.168.9.159|192.168.9.160|192.168.9.161|192.168.9.162|192.168.9.163|192.168.9.164|192.168.9.165|192.168.9.166|192.168.9.167|192.168.9.168|192.168.9.169|192.168.9.170|192.168.9.171|192.168.9.172|192.168.9.173|192.168.9.174|192.168.9.175|192.168.9.176|192.168.9.177|192.168.9.178|192.168.9.179|192.168.9.180|192.168.9.181|192.168.9.182|192.168.9.183|192.168.9.184|192.168.9.185|192.168.9.186|192.168.9.187|192.168.9.188|192.168.9.189|192.168.9.190|192.168.9.191|192.168.9.192|192.168.9.193|192.168.9.194|192.168.9.195|192.168.9.196|192.168.9.197|192.168.9.198|192.168.9.199|192.168.9.200|192.168.9.201|192.168.9.202|192.168.9.203|192.168.9.204|192.168.9.205|192.168.9.206|192.168.9.207|192.168.9.208|192.168.9.209|192.168.9.210|192.168.9.211|192.168.9.212|192.168.9.213|192.168.9.214|192.168.9.215|192.168.9.216|192.168.9.217|192.168.9.218|192.168.9.219|192.168.9.220|192.168.9.221|192.168.9.222|192.168.10.3|192.168.10.4|192.168.10.5|192.168.10.6|192.168.10.7|192.168.10.8|192.168.10.9|192.168.10.10|192.168.10.11|192.168.10.12|192.168.10.13|192.168.10.14|192.168.10.15|192.168.10.16|192.168.10.17|192.168.10.18|192.168.10.19|192.168.10.20|192.168.10.21|192.168.10.22|192.168.10.23|192.168.10.24|192.168.10.25|192.168.10.26|192.168.10.27|192.168.10.28|192.168.10.29|192.168.10.30|192.168.10.31|192.168.10.32|192.168.10.33|192.168.10.34|192.168.10.35|192.168.10.36|192.168.10.37|192.168.10.38|192.168.10.39|192.168.10.40|192.168.10.41|192.168.10.42|192.168.10.43|192.168.10.44|192.168.10.45|192.168.10.46|192.168.10.47|192.168.10.48|192.168.10.49|192.168.10.50|192.168.10.51|192.168.10.52|192.168.10.53|192.168.10.54|192.168.10.55|192.168.10.56|192.168.10.57|192.168.10.58|192.168.10.59|192.168.10.60|192.168.10.61|192.168.10.62|192.168.10.63|192.168.10.64|192.168.10.65|192.168.10.66|192.168.10.67|192.168.10.68|192.168.10.69|192.168.10.70|192.168.10.71|192.168.10.72|192.168.10.73|192.168.10.74|192.168.10.75|192.168.10.76|192.168.10.77|192.168.10.78|192.168.10.79|192.168.10.80|192.168.10.81|192.168.10.82|192.168.10.83|192.168.10.84|192.168.10.85|192.168.10.86|192.168.10.87|192.168.10.88|192.168.10.89|192.168.10.90|192.168.10.91|192.168.10.92|192.168.10.93|192.168.10.94|192.168.10.95|192.168.10.96|192.168.10.97|192.168.10.98|192.168.10.99|192.168.10.100|192.168.10.101|192.168.10.102|192.168.10.103|192.168.10.104|192.168.10.105|192.168.10.106|192.168.10.107|192.168.10.108|192.168.10.109|192.168.10.110|192.168.10.111|192.168.10.112|192.168.10.113|192.168.10.114|192.168.10.115|192.168.10.116|192.168.10.117|192.168.10.118|192.168.10.119|192.168.10.120|192.168.10.121|192.168.10.122|192.168.10.123|192.168.10.124|192.168.10.125|192.168.10.126|192.168.10.127|192.168.10.128|192.168.10.129|192.168.10.130|192.168.10.131|192.168.10.132|192.168.10.133|192.168.10.134|192.168.9.28|192.168.9.29"
# 需要进行网络不可达检验的公网ip及端口号，多个以|号分割)
net_ip = "192.168.9.6 22"
# 存储挂载路径及磁盘剩余空间监测，填写需要监测的磁盘挂载目录，若为根目录挂载可以直接填写`/`，多个挂载目录使用`|`进行分隔
file_mount = "/"
# 阵列卡磁盘个数
raid_disk_num = 36
# 剩余磁盘空间监测，默认是单位是G，监测的目录为`file_mount`中填写的路径
disk_avail_alert = 150
# 是否开启每日简报，每日简报默认运行在Wining-Miner机器上，默认每天上午12点进行推送，同时该功能需要获取其他运行告警脚本机器上的日志信息
daily_summary = True
# 每日简报准点发送时间，如12即每天上午12时发送
daily_summary_time = "12"
# 所有运行该告警脚本的机器内网ip，以|号分割，用来收集所有机器告警脚本日志中的信息
collection_ip = "192.168.7.11|192.168.7.12|192.168.7.13|192.168.6.11|192.168.2.11"
# 所有运行该脚本的机器的告警日志路径（建议所有机器告警日志在同一目录下）
alert_log_path = "/root/sub_alert/sub_alert.log"
# WindowPost—Miner日志路径「选填，在WindowPost-Miner上运行时需要填写」
wdpost_log_path = "/home/ps/miner.log"
# fil_account 为你的Miner节点号「必填，用于爆块检测」
fil_account = "AI3"
# 最长时间任务告警，p1默认是小时，p2默认是分钟，c默认是分钟，「选填」
p1_job_time_alert = 5
p2_job_time_alert = 40
c2_job_time_alert = 25
# Default钱包余额告警阈值「选填，默认50」
default_wallet_balance = 20
# check_interval 程序循环检查间隔默认300秒
check_interval = 300
# ssh 登录授权IP地址,以|号分割，如果登录IP不在列表中，将发出告警消息。
ssh_white_ip_list = "192.168.85.10|221.10.1.1"


def print(s, end="\n", file=sys.stdout):
    file.write(s + end)
    file.flush()


def is_number(s):
    try:
        float(s)
        return True
    except ValueError:
        pass

    try:
        import unicodedata

        unicodedata.numeric(s)
        return True
    except (TypeError, ValueError):
        pass
    return False


def is_valid_date(strdate):
    try:
        time.strptime(strdate, "%a %b %d %H:%M:%S %Y")
        return True
    except:
        return False


def today_anytime_tsp(hour):
    minute = 0
    second = 0
    now = datetime.now()
    today_0 = now - timedelta(hours=now.hour, minutes=now.minute, seconds=now.second)
    today_anytime = today_0 + timedelta(hours=hour, minutes=minute, seconds=second)
    tsp = today_anytime.timestamp()
    return tsp


def server_post(title="", content="默认正文"):
    global send_key
    global fil_account
    global openid
    global daily_summary
    api = "https://sctapi.ftqq.com/" + send_key + ".send"
    title = fil_account + ":" + title
    data = {"text": title, "desp": content, "openid": openid}
    try:
        req = requests.post(api, data=data)
        req_json = json.loads(req.text)
        if req_json.get("data").get("errno") == 0:
            print("server message sent successfully: " + machine_name + " | " + content)
            return True
        else:
            # print("server message sent failed: " + req.text)
            return False
    except requests.exceptions.RequestException as req_error:
        return False
        print("Request error: " + req_error)
    except Exception as e:
        return False
        print("Fail to send message: " + e)


# 高度同步检查
def chain_check():
    try:
        out = sp.getoutput("timeout 36s lotus sync wait")
        print("chain_check:")
        print(out)
        if out.endswith("Done!"):
            print("true")
            return True
        server_post(machine_name, "节点同步出错，请及时排查！")
        return False
    except Exception as e:
        print("Fail to send message: " + e)


# 显卡驱动检查
def nvidia_check():
    out = sp.getoutput("timeout 30s echo $(nvidia-smi | grep GeForce)")
    print("nvidia_check:")
    print(out)
    if out.find("GeForce") >= 0:
        print("true")
        return True
    server_post(machine_name, "显卡驱动故障，请及时排查！")
    return False


# miner进程检查
def minerprocess_check():
    time.sleep(5)
    out = sp.getoutput("timeout 30s echo $(pidof lotus-miner)")
    print("minerprocess_check:")
    print(out)
    if out.strip():
        print("true")
        return True
    server_post(machine_name, "Miner进程丢失，请及时排查！")
    return False


# lotus进程检查
def lotusprocess_check():
    out = sp.getoutput("timeout 30s echo $(pidof lotus)")
    print("lotusprocess_check:")
    print(out)
    if out.strip():
        print("true")
        return True
    server_post(machine_name, "Lotus进程丢失，请及时排查！")
    print("false")
    return False


# 消息堵塞检查
def mpool_check():
    out = sp.getoutput("lotus mpool pending --local | wc -l")
    print("mpool_check:")
    print(out)
    if is_number(out):
        if int(out) <= 240:
            print("true")
            return True
        server_post(machine_name, "消息堵塞，请及时清理！")
    return False


# 存储文件挂载检查，磁盘容量剩余检查
def fm_check(check_type=""):
    global file_mount
    is_fm_correct = True
    fs = file_mount.split("|")
    for str in fs:
        out = sp.getoutput(
            "timeout 30s echo $(df -h |awk '{print $6,$4}'|grep -w "
            + str
            + " |awk '{print $2}'"
            + ")"
        )
        print("fm_check:")
        print(out)
        if not out.strip():
            print("false")
            server_post(machine_name, "未发现存储挂载目录，请及时排查！")
            is_fm_correct = False
        if not (out.find("T") >= 0):
            match = re.search(r"(\d+(\.\d+)?)", out)
            if match and float(match.group(1)) <= disk_avail_alert:
                print("false")
                server_post(machine_name, "磁盘空间不足，请及时排查！")
                is_fm_correct = False
    return is_fm_correct


# WindowPost—Miner日志报错检查
def wdpost_log_check():
    out = sp.getoutput("cat " + wdpost_log_path + "| grep 'running window post failed'")
    print("wdpost_log_check:")
    print(out)
    if not out.strip():
        print("true")
        return True
    server_post(machine_name, "Wdpost报错，请及时处理！")
    return False


# WiningPost—Miner爆块检查
def mined_block_check(chain_time):
    mined_block_cmd = "lotus chain list --count {0} |grep {1} |wc -l".format(
        int(chain_time / 30), fil_account
    )
    out = sp.getoutput(mined_block_cmd)
    print("mined_block_check:")
    print(out)
    block_count = int(out)
    if block_count > 0 and not daily_summary:
        server_post(
            machine_name,
            "{0}又爆了{1}个块".format(fil_account, block_count)
            + "，大吉大利，今晚吃鸡",
        )
    return out


# P1任务超时检查
def p1_overtime_check():
    global p1_job_time_alert
    out = sp.getoutput(
        "lotus-miner sealing jobs | grep -w PC1 | awk '{ print $7}' | head -n 1 | tail -n 1"
    )
    print("overtime_check:")
    print(out)
    if (out.find("Time") >= 0) or (not out.find("h") >= 0):
        print("time true")
        return True
    if out.strip() and int(out[0 : out.find("h")]) <= p1_job_time_alert:
        print(out[0 : out.find("h")])
        print("true")
        return True
    server_post(machine_name, "P1封装任务超时，请及时处理！")
    return False


# P2任务超时检查
def p2_overtime_check():
    global p2_job_time_alert
    out = sp.getoutput(
        "lotus-miner sealing jobs | grep -w PC2 | awk '{ print $7}' | head -n 1 | tail -n 1"
    )
    print("overtime_check:")
    print(out)
    if not out.find("h") >= 0:
        if (out.find("Time") >= 0) or (not out.find("m") >= 0):
            print("time true")
            return True
        if out.strip() and int(out[0 : out.find("m")]) <= p2_job_time_alert:
            print(out[0 : out.find("m")])
            print("true")
            return True
    else:
        time_parts = out.split("h")
        hours = int(time_parts[0])
        minutes_parts = time_parts[1].split("m")
        minutes = int(minutes_parts[0])
        total_minutes = hours * 60 + minutes
        if total_minutes <= p2_job_time_alert:
            return True
    server_post(machine_name, "P2封装任务超时，请及时处理！")
    return False


# C2任务超时检查
def c2_overtime_check():
    global c2_job_time_alert
    out = sp.getoutput(
        "lotus-miner sealing jobs | grep -w C2 | awk '{ print $7}' | head -n 1 | tail -n 1"
    )
    print("overtime_check:")
    print(out)
    if not out.find("h") >= 0:
        if (out.find("Time") >= 0) or (not out.find("m") >= 0):
            print("time true")
            return True
        if out.strip() and int(out[0 : out.find("m")]) <= c2_job_time_alert:
            print(out[0 : out.find("m")])
            print("true")
            return True
    server_post(machine_name, "C2封装任务超时，请及时处理！")
    return False


# Default钱包余额预警
def balance_check():
    global default_wallet_balance
    out = sp.getoutput("lotus wallet balance")
    print("balance_check:")
    print(out)
    balance = out.split(" ")
    if is_number(balance[0]):
        if float(balance[0]) < default_wallet_balance:
            post_str = (
                "钱包余额为:" + str(int(float(balance[0]))) + " Fil，请及时充值！"
            )
            print(post_str)
            return False
    return True


# 检查内网服务器是否可达（宕机或网络不通）
def reachable_check():
    try:
        global server_ip
        is_reachable = True
        ips = server_ip.split("|")
        print("reachable_check:")
        for ip in ips:
            print(ip)
            p = sp.Popen(
                ["ping -c 1 -W 1 " + ip], stdout=sp.PIPE, stderr=sp.PIPE, shell=True
            )
            out = p.stdout.read()
            regex = re.compile("100% packet loss")
            if len(regex.findall(str(out))) != 0:
                print("false")
                server_post(
                    machine_name,
                    str(ip) + "，服务器不可达（宕机/网络故障），请及时排查！",
                )
                is_reachable = False
            time.sleep(1)
        return is_reachable
    except:
        print("reachable_check error!")


# ssh 登录IP是否授权检查
def ssh_login_ip_check():
    try:
        global ssh_white_ip_list
        print("ssh logined ip check:\n")
        hostname = sp.getoutput("hostname")
        # 获取已登录用户IP地址列表
        out = sp.getoutput("who |grep -v tmux |awk '{print $5}'")
        out = out.replace("(", "").replace(")", "")
        login_ip_list = out.split("\n")
        # 去除重复
        login_ip_list = set(login_ip_list)
        login_ip_list = list(login_ip_list)
        # 把ssh登录授权IP地址格式化成列表
        ssh_white_ip_list = ssh_white_ip_list.split("|")
        # 检测已登录IP是否授权
        for ip in login_ip_list:
            if ip != "" and ip not in ssh_white_ip_list:
                curtime = time.strftime(
                    "%Y-%m-%d %H:%M:%S", time.localtime(time.time())
                )
                msg = "{0},未授权IP:{1},已登录服务器{2}".format(curtime, ip, hostname)
                server_post(machine_name, hostname + msg)
        print("--------ssh logined ip check finished -------------")
    except Exception as e:
        print(str(e))


# 扇区证明出错检查
def sectors_fault_check():
    global sector_faults_num
    sectors_fault_cmd = "lotus-miner proving faults|wc -l"
    out = sp.getoutput(sectors_fault_cmd)
    print("sectors_fault_check:")
    print(out)
    sectors_count = int(out) - 2
    if sectors_count > 0:
        if sectors_count > sector_faults_num:
            sector_faults_num = sectors_count
            server_post(
                machine_name,
                "{0}节点出错{1}个扇区".format(fil_account, sectors_count)
                + "，请及时处理",
            )
        return False
    if sectors_count == 0:
        sector_faults_num = 0
    return True


# 阵列卡故障盘检测
def raid_offline_check():
    out = sp.getoutput("sudo  MegaCli64 -PDList -aALL|grep -c 'Firmware state'")
    print("raid_offline_check:")
    print(out)
    if is_number(out):
        if int(out) < raid_disk_num:
            print("false")
            server_post(machine_name, "阵列卡磁盘出现丢失，请及时处理！")
            return False
    return True


# 阵列卡预警盘检测
def raid_critical_check():
    out = sp.getoutput(
        "sudo MegaCli64 -AdpAllInfo -aALL | grep 'Critical Disks' | awk '{print $4}'"
    )
    print("raid_critical_check:")
    print(out)
    if is_number(out):
        if int(out) > 0:
            print("false")
            server_post(machine_name, "阵列卡出现预警盘，请注意！")
            return False
    return True


# 阵列卡磁盘坏道检测
def raid_error_check():
    out = sp.getoutput("sudo MegaCli64 -PDList -aALL|grep Error|awk '{print $4}'")
    print("raid_error_check:")
    res = str(out).split()
    # print(out)
    print(str(res))
    for array in res:
        if int(array) > 10:
            server_post(machine_name, "磁盘出现坏道，请注意！")
            return False
    return True


# 阵列卡磁盘故障/bad检测
def raid_failed_check():
    out = sp.getoutput("sudo  MegaCli64 -PDList -aALL|grep  state|grep -E 'Failed|bad'")
    print("raid_failed_check:")
    print(out)
    if not out.strip():
        print("true")
        return True
    server_post(machine_name, "阵列卡出现故障盘，请及时处理！")
    return False


# 检查公网服务器是否可达
def net_check(check_type=""):
    global net_ip
    is_ip_reach = True
    ips = net_ip.split("|")

    for ip in ips:
        success = False
        for attempt in range(2):  # 尝试两次
            out = sp.getoutput(f"timeout 3s nc -zv {ip}")
            print("net_check:")
            print(out)
            if "succeeded" in out:
                print("true")
                success = True
                break
            time.sleep(5)  # 每次尝试之间等待1秒

        if not success:
            print("false")
            server_post(machine_name, f"{ip} 不可达，请及时排查！")
            is_ip_reach = False

    return is_ip_reach


# 每日简报汇集
def daily_collection():
    global collection_ip
    global alert_log_path
    res_string = ""
    check_status = True
    ips = collection_ip.split("|")
    now = time.time()
    time_flow = abs(int(now) - int(today_anytime_tsp(int(daily_summary_time))))
    if int(time_flow) <= (int(check_interval) / 2):
        for ip in ips:
            out = sp.getoutput(
                "timeout 30s ssh  "
                + ip
                + " cat "
                + alert_log_path
                + " | grep -a -A 1 Check | sed '$!d'"
            )
            if is_valid_date(out):
                timestamp = int(time.mktime(time.strptime(out, "%a %b %d %H:%M:%S %Y")))
                if (int(now) - timestamp) > int(check_interval + 300):
                    res_string = res_string + ip + "、"
                    check_status = False
            else:
                check_status = False
                res_string = res_string + ip + "、"
        if check_status:
            res_string = "告警脚本正常运行。"
        else:
            res_string = res_string + "机器告警脚本无法获取或可能出现故障，请及时查看。"
        if sectors_fault_check():
            res_string = res_string + "今日节点无扇区出错。"
        else:
            res_string = res_string + "今日节点有扇区出错，请及时处理。"
        res_string = (
            res_string + "今日节点爆了" + mined_block_check(86400) + "个块，大吉大利!"
        )
        server_post("每日简报", res_string)


def delete_pod_by_ip(ip, namespace="kubesub"):
    try:
        get_pod_cmd = f"kubectl get pods -n {namespace} -o wide | grep -w {ip} | awk '{{print $1}}' | head -n 1"
        pod_name = sp.check_output(get_pod_cmd, shell=True, text=True).strip()
        if pod_name:
            print(f"Deleting pod {pod_name} for IP {ip}")
            sp.run(f"kubectl delete pod {pod_name} -n {namespace}", shell=True)
        else:
            print(f"No pod found for IP {ip}")
    except Exception as e:
        print(f"Failed to delete pod for IP {ip}: {e}")


def fetch_ip_values():
    cmd = [
        "curl",
        "-u",
        "admin:prom-operator",
        "-G",
        "http://localhost:3000/api/datasources/proxy/1/api/v1/query",
        "--data-urlencode",
        "query=sum(rate(kubesub_auditor_auditing_sectors_total[5m])) by (exported_instance)",
    ]
    response = sp.run(cmd, stdout=sp.PIPE, stderr=sp.PIPE, text=True)

    if response.returncode != 0:
        print("请求失败：", response.stderr)
        exit(1)

    data = json.loads(response.stdout)
    results = data.get("data", {}).get("result", [])
    return {
        item["metric"]["exported_instance"]: float(item["value"][1]) for item in results
    }


def fetch_power_total():
    try:
        cmd = [
            "curl",
            "-u",
            "admin:prom-operator",
            "-G",
            "http://localhost:3000/api/datasources/proxy/1/api/v1/query",
            "--data-urlencode",
            "query=sum(rate(kubesub_auditor_auditing_sectors_total[5m]))",
        ]
        response = sp.run(cmd, stdout=sp.PIPE, stderr=sp.PIPE, text=True)
        if response.returncode != 0:
            print("Prometheus 请求失败：", response.stderr)
            return None

        data = json.loads(response.stdout)
        result = data.get("data", {}).get("result", [])
        if result and "value" in result[0]:
            raw_value = float(result[0]["value"][1])
            gib_value = raw_value / 1000 / 1000
            return gib_value
        return None
    except Exception as e:
        print("解析 Prometheus 数据出错：", e)
        return None


def rate_collection():
    ip_list = server_ip.strip().split("|")

    # 第一次获取 Prometheus 指标
    ip_values = fetch_ip_values()

    # 第一次筛选异常 IP
    problem_ips = []
    for ip in ip_list:
        if ip not in ip_values or ip_values[ip] / 1024 < 10:
            delete_pod_by_ip(ip)
            problem_ips.append(ip)

    if not problem_ips:
        return True  # 没有问题 IP，直接返回

    # 等待 5 分钟
    print("等待 5 分钟以检查 pod 重建后的状态...")
    time.sleep(300)

    # 第二次检测
    ip_values = fetch_ip_values()
    for ip in problem_ips:
        if ip not in ip_values:
            server_post("算力检测", f"{ip} 算力丢失，请及时处理！")
        elif ip_values[ip] / 1024 < 10:
            server_post(
                "算力检测",
                f"{ip} 算力异常（{ip_values[ip]/1024:.2f} TiB），请及时处理！",
            )
    return False


def AI3_daily_collection():
    global collection_ip
    global alert_log_path
    res_string = ""
    check_status = True
    ips = collection_ip.split("|")
    now = time.time()
    time_flow = abs(int(now) - int(today_anytime_tsp(int(daily_summary_time))))

    if int(time_flow) <= int(check_interval):
        # ✅ 本机日志检查（不再通过 ssh）
        try:
            out = sp.getoutput(
                "cat " + alert_log_path + " | grep -a -A 1 Check | sed '$!d'"
            )
            if is_valid_date(out):
                timestamp = int(time.mktime(time.strptime(out, "%a %b %d %H:%M:%S %Y")))
                if (int(now) - timestamp) > int(check_interval + 300):
                    res_string += "本机日志时间过旧，"
                    check_status = False
            else:
                res_string += "未能正确获取本机日志时间，"
                check_status = False
        except Exception as e:
            res_string += "读取本机日志失败，"
            check_status = False

        if check_status:
            res_string += "告警脚本正常运行。"
        else:
            res_string += "机器告警脚本无法获取或可能出现故障，请及时查看。"

        # ✅ 添加总算力（TiB）
        power_gib = fetch_power_total()
        if power_gib is not None:
            res_string += f" 当前总算力为 {power_gib:.2f} PiB。"
        else:
            res_string += " 无法获取当前总算力。"

        server_post("每日简报", res_string)


def loop():
    global sector_faults_num
    sector_faults_num = 0
    while True:
        try:
            start_time = time.time()
            global check_machine
            global fil_account
            if not check_machine.strip():
                print("请填写巡检的机器类型！")
                break
            if reachable_check():
                print("各服务器均可达，无异常")
            if net_check():
                print("各公网均可达，无异常")
            if check_machine.find("一") >= 0:
                if rate_collection():
                    if daily_summary:
                        AI3_daily_collection()
                    print("AI3已巡检完毕，无异常")
            time.sleep(3)
            if check_machine.find("二") >= 0:
                if (
                    minerprocess_check()
                    and p1_overtime_check()
                    and p2_overtime_check()
                    and c2_overtime_check()
                ):
                    print("Seal-Miner已巡检完毕，无异常")
            time.sleep(3)
            if check_machine.find("三") >= 0:
                if daily_summary:
                    daily_collection()
                else:
                    mined_block_check(int(check_interval))
                if nvidia_check() and minerprocess_check():
                    print("WiningPost-Miner已巡检完毕，无异常")
            time.sleep(3)
            if check_machine.find("四") >= 0:
                if (
                    nvidia_check()
                    and minerprocess_check()
                    and wdpost_log_check()
                    and sectors_fault_check()
                ):
                    print("WindowPost-Miner已巡检完毕，无异常")
            time.sleep(3)
            if check_machine.find("五") >= 0:
                if (
                    raid_offline_check()
                    and raid_error_check()
                    and raid_critical_check()
                    and raid_failed_check()
                ):
                    print("存储机已巡检完毕，无异常")
            print("----------Check End-----------")
            print(time.asctime(time.localtime(time.time())))
            end_time = time.time()
            sleep_time = check_interval - (end_time - start_time)
            # sleep
            print("sleep {0} seconds\n".format(check_interval))
            time.sleep(check_interval)
        except KeyboardInterrupt:
            exit(0)
        except:
            traceback.print_exc()
            time.sleep(120)


def main():
    loop()


if __name__ == "__main__":
    # init_check()
    main()
