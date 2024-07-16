# 设置默认输出文件的编码（如果需要的话）
$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'
$data = @{"project"=@()} 
# 导出安全策略到当前目录
secedit /export /cfg config.cfg /quiet

#账户检查
$userAccounts = Get-WmiObject -Class Win32_UserAccount  
# echo $userAccounts
# $projectdata = @{"msg"="当前终端存在的账户：$($userAccounts.Name -join ', ')";}  
# $data['project']+=$projectdata	
$data.project += @{"msg" = "当前终端存在的账户：$($userAccounts.Name -join ', ')"} 
$data.project += @{"msg" = "   "}

#IP检查
# $IPInfo = Get-NetIPAddress
# echo  "IPInfo: " $IPInfo
$data.project += @{"msg" = "Windows IP 配置："}
$data.project += @{"msg" = "   "}

# 获取所有网络适配器
$netAdapters = Get-NetAdapter
# 遍历所有网络适配器
foreach ($adapter in $netAdapters) {
    if ($adapter.Status) { # 只处理启用的适配器 -eq "Up"
        $data.project += @{"msg" = "以太网适配器 $($adapter.Name):"}
        $data.project += @{"msg" = "   连接特定的 DNS 后缀 . . . . . . . . . . . :"}
        # 获取适配器的 IP 地址配置
        $ipAddresses = Get-NetIPAddress -InterfaceAlias $adapter.InterfaceAlias
        foreach ($ip in $ipAddresses) {
            if ($ip.AddressFamily -eq "IPv6") {
                $data.project += @{"msg" = "   本地链接 IPv6 地址. . . . . . . . . . . . . . : $($ip.IPAddress)"}
            } elseif ($ip.AddressFamily -eq "IPv4") {
                $data.project += @{"msg" = "   IPv4 地址. . . . . . . . . . . . . . . . . . . : $($ip.IPAddress)"}
            }
        }
        
        # 获取适配器的子网掩码和默认网关
        $defaultGateway = Get-NetRoute -InterfaceAlias $adapter.InterfaceAlias -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1
        if ($defaultGateway) {
            $data.project += @{"msg" = "   默认网关. . . . . . . . . . . . . : $($defaultGateway.NextHop)"}
        } else {
            $data.project += @{"msg" = "   默认网关. . . . . . . . . . . . . :  "}
        }
        # TODO:还有点小问题需要修正
        # #输出子网掩码  
        # $subnetMask = ($ipAddresses | Where-Object {$_.AddressFamily -eq "IPv4"} | Select-Object -ExpandProperty PrefixLength)
        # if ($subnetMask) {
        #     $data.project += @{"msg" ="   子网掩码  . . . . . . . . . . . . . :" + (Convert-MaskToSubnet $subnetMask)}
        # } else {
        #     $data.project += @{"msg" ="   子网掩码  . . . . . . . . . . . . . : "}
        # }

        #空行
        $data.project += @{"msg" = "   "}
       
    }
}

# #net检查
# $netInfo = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
# Write-Host "Network Adapter Status:"
# $data.project += @{"msg" = $netInfo} 

#系统信息检查
$systemInfo = systemInfo
# echo  "SystemInfo: " $systeminfo
$data.project += @{"msg" = $systemInfo} 




# 读取安全策略配置文件
$config = Get-Content -path config.cfg
# echo $config

# 遍历配置文件，检查各个策略  
foreach ($line in $config) {  
    $config_line = $line -split "="  
    $key = $config_line[0].Trim()  
    $value = $config_line[1].Trim()  
    
    #[系统访问]
    #检查密码最长使用期限策略
    if ($key -eq "MaximumPasswordAge") {
        $msg = if ($value -eq "90") { "密码最长使用期限策略符合标准"} else { "密码最长使用期限策略不符合标准"}
        $msg = $msg + ":长期不修改密码会提高密码暴露风险,所以为了提高系统的保密性.需要检查密码最长使用期限."
        $data.project += @{"msg" = $msg}  
    }

    #检查密码长度最小值策略
    if ($key -eq "MinimumPasswordLength") {
        $msg = if ($value -eq "8") { "密码最小值策略符合标准"} else { "密码最小值策略不符合标准"}
        $msg = $msg + ":长度小的口令存在被爆破出的风险,所以为了保证密码的安全,提高保密性需要检查口令最小长度"
        $data.project += @{"msg" = $msg}  
    }

    # 检查密码复杂性策略  
    if ($key -eq "PasswordComplexity") {  
        $msg = if ($value -eq "1") { "密码复杂性策略符合标准" } else { "密码复杂性策略不符合标准" }  
        $msg = $msg + ":仅包含字母数字字符的密码可通过多种公开可用的工具轻松发现."
        $data.project += @{"msg" = $msg}  
    } 

    # 检查强制密码历史个数
    if ($key -eq "PasswordHistorySize") {
        $msg = if ($value -eq "2") { "强制密码历史策略符合标准"} else { "强制密码历史策略不符合标准"}
        $msg = $msg + ":强制密码历史的意思是,系统会记住以前的密码历史,在修改密码的时候不可与以前的密码相同,修改相同的密码会提高密码的暴露性."
        $data.project += @{"msg" = $msg}  
    }

    #检查账户锁定阀值策略
    if ($key -eq "LockoutBadCount") {
        $msg = if ($value -eq "8") { "账户锁定阀值策略符合标准"} else { "账户锁定阀值策略不符合标准"}
        $msg = $msg + ":此安全设置确定导致用户帐户被锁定的登录尝试失败的次数."
        $data.project += @{"msg" = $msg}  
    }

    # #检查账户锁定时间策略
    # if ($key -eq "ResetLockoutCount") {
    #     $msg = if ($value -eq "30") { "账户锁定时间策略符合标准"} else { "账户锁定时间策略不符合标准"}
    #     $msg = $msg + ":用户登录失败次数过多应对服务器登录进行锁定,防止密码被爆破到风险."
    #     $data.project += @{"msg" = $msg}  
    # }

    # #检查复位账户锁定计数器时间策略
    # if ($key -eq "LockoutDuratio") {
    #     $msg = if ($value -eq "30") { "复位账户锁定计数器时间策略符合标准"} else { "复位账户锁定计数器时间策略不符合标准"}
    #     $msg = $msg + ":此安全设置确定锁定状态的持续时间,复位账户锁定计数器是指确定登录尝试失败之后和登录尝试失败计数器被复位为 0 次失败登录尝试之前经过的分钟数.有效范围为 1 到 99,999 分钟之间"
    #     $data.project += @{"msg" = $msg}  
    # }

    #检查*下次登录必须更改密码策略
    if ($key -eq "RequireLogonToChangePassword") {
        $msg = if ($value -eq "0") { "*下次登录必须更改密码策略符合标准"} else { "*下次登录必须更改密码策略不符合标准"}
        $data.project += @{"msg" = $msg}  
    }

    #检查*强制过期策略
    if ($key -eq "ForceLogoffWhenHourExpire") {
        $msg = if ($value -eq "0") { "*强制过期策略符合标准" } else { "*强制过期策略不符合标准" }
        $data.project += @{"msg" = $msg}  
    }

    #检查管理员名称
    if ($key -eq "NewAdministratorName") {
        $msg = if ($value -eq "Administrator") { "管理员名称符合标准"} else { "管理员名称不符合标准"}
        $data.project += @{"msg" = $msg}  
    }

    #检查来宾用户命名
    if ($key -eq "NewGuestName") {
        $msg = if ($value -eq "Guest") { "来宾用户名称符合标准"} else { "来宾用户名称不符合标准"}
        $data.project += @{"msg" = $msg}  
    }

    #检查Administartor账户停用策略
    if ($key -eq "EnableAdminAccount") {
        $msg = if ($value -eq "1") { "Administartor账户停用策略符合标准"} else { "Administartor账户停用策略不符合标准"}
        $data.project += @{"msg" = $msg}  
    }

    # 检查guest账户停用策略  
    if ($key -eq "EnableGuestAccount") {  
        $msg = if ($value -eq "1") { "guest账户停用策略符合标准" } else { "guest账户停用策略不符合标准" }  
        $data.project += @{"msg" = $msg}  
    }  
  
    # [事件审计]
    #审核系统事件  检查是否开启策略更改审核
    if ($key -eq "AuditSystemEvents") {   
        $msg = if ($value -eq "3") { "审核系统事件策略符合标准"} else { "审核系统事件策略不符合标准"}
        $msg = $msg + ":服务器排错与维护是服务器开发必不可少到部分,故对日志文件到配置与管理尤为重要."
        $data.project += @{"msg" = $msg}
    }
    
    #审核登录事件 检查是否开启登录事件审核
    if ($key -eq "AuditLogonEvents") {   
        $msg = if ($value -eq "3") { "审核登录事件策略符合标准"} else { "审核登录事件策略不符合标准"}
        $msg = $msg + ":服务器排错与维护是服务器开发必不可少到部分,故对日志文件到配置与管理尤为重要."
        $data.project += @{"msg" = $msg}
    }

    #审核对象访问
    if ($key -eq "AuditObjectAccess") {   
        $msg = if ($value -eq "3") { "审核对象访问策略符合标准"} else { "审核对象访问策略不符合标准"}
        $msg = $msg + ":服务器排错与维护是服务器开发必不可少到部分,故对日志文件到配置与管理尤为重要."
        $data.project += @{"msg" = $msg}
    }

    #审核特权使用
    if ($key -eq "AuditPrivilegeUse") {   
        $msg = if ($value -eq "3") { "审核特权使用策略符合标准"} else { "审核特权使用策略不符合标准"}
        $msg = $msg + ":服务器排错与维护是服务器开发必不可少到部分,故对日志文件到配置与管理尤为重要."
        $data.project += @{"msg" = $msg}
    }

    #审核特权更改
    if ($key -eq "AuditPolicyChange") {   
        $msg = if ($value -eq "3") { "审核特权更改策略符合标准"} else { "审核特权更改策略不符合标准"}
        $data.project += @{"msg" = $msg}
    }

    #审核账户管理
    if ($key -eq "AuditAccountManage") {   
        $msg = if ($value -eq "2") { "审核账户管理策略符合标准"} else { "审核账户管理策略不符合标准"} 
        $msg = $msg + ":服务器排错与维护是服务器开发必不可少到部分,故对日志文件到配置与管理尤为重要"  
        $data.project += @{"msg" = $msg}
    }
    
    #审核进程跟踪
    if ($key -eq "AuditProcessTracking") {   
        $msg = if ($value -eq "2") { "审核进程跟踪策略符合标准"} else { "审核进程跟踪策略不符合标准"}
        $msg = $msg + ":服务器排错与维护是服务器开发必不可少到部分,故对日志文件到配置与管理尤为重要."
        $data.project += @{"msg" = $msg}
    }

    #审核目录服务访问
    if ($key -eq "AuditDSAccess") {   
        $msg = if ($value -eq "3") { "审核目录服务访问策略符合标准"} else { "审核目录服务访问策略不符合标准"}
        $msg = $msg + ":服务器排错与维护是服务器开发必不可少到部分,故对日志文件到配置与管理尤为重要."   
        $data.project += @{"msg" = $msg}
    }

    #审核账户登录事件
    if ($key -eq "AuditAccountLogon") {   
        $msg = if ($value -eq "2") { "审核账户登录事件策略符合标准"} else { "审核账户登录事件策略不符合标准"}   
        $msg = $msg + ":服务器排错与维护是服务器开发必不可少到部分,故对日志文件到配置与管理尤为重要."
        $data.project += @{"msg" = $msg}
    }


    # [特权权利]
    #从网络访问此计算机策略
    if ($key -eq "SeNetworkLogonRight") {   
        $msg = if ($value -eq "*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551") { "从网络访问此计算机策略符合标准"} else { "从网络访问此计算机策略不符合标准"}
        $data.project += @{"msg" = $msg}
    }  

    #操作系统远程关机策略安全
    if ($key -eq "SeRemoteShutdownPrivilege") {
        $msg = if ($value -eq "*S-1-5-32-544") { "操作系统远程关机策略符合标准"} else { "操作系统远程关机策略不符合标准"}
        $msg = $msg + "：可以远端关闭系统的账户和组必须是管理员权限和组,所以为了提高系统的可靠性,需要检查是否限制关闭系统的账户和组."
        $data.project += @{"msg" = $msg}  
    }

    #操作系统本地关机策略安全 检查可关闭系统的帐户和组
    if ($key -eq "SeShutdownPrivilege") {
        $msg = if ($value -eq "*S-1-5-32-544") { "操作系统本地关机策略符合标准"} else { "操作系统本地关机策略不符合标准"}
        $msg = $msg + "：可以关闭系统的账户和组必须是管理员权限和组,所以为了提高系统的可靠性,需要检查是否限制关闭系统的账户和组."
        $data.project += @{"msg" = $msg}  
    }

    #取得文件或其他对象的所有权限策略
    if ($key -eq "SeProfileSingleProcessPrivilege") {
        $msg = if ($value -eq "*S-1-5-32-544") { "取得文件或其他对象的所有权限策略符合标准"} else { "取得文件或其他对象的所有权限策略不符合标准"}
        $msg = $msg + "：分配此用户权限可能会带来安全风险. 由于对象的所有者可以完全控制它们,因此仅向受信任的用户分配此用户权限."
        $data.project += @{"msg" = $msg}  
    }



    # [注册表值]
    #检查可远程访问的注册表路径和子路径
    if ($key -eq "MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\Machine") {
        $config_line = $value -split ","
        $value = $config_line[1].Trim() 
        $data.project += @{"msg" = $value}
    }

    # #检查是否已删除可匿名访问的共享和命名管道
    # if ($key -eq "MACHINE\SYSTEM\ControlSet001\services\LanmanServer\Parameters\NullSessionPipes") {
    #     $config_line = $value -split ","
    #     $value = $config_line[1].Trim()
    #     if ($value -like " "){
    #         $data.project += @{"msg" = "空值"}
    #     }
    #     else {
    #         $data.project += @{"msg" = $value}
    #     }
    # }

  

    #暂停会话前所需的空闲时间
    if ($key -eq "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\AutoDisconnect") {
	    $config_line = $value -split ","
        # echo $config_line
        $value = $config_line[1].Trim() 
        $msg = if ([int]$value -le "30") { "暂停会话前所需的空闲时间策略符合标准"} else { "暂停会话前所需的空闲时间策略不符合标准"}
        $data.project += @{"msg" = $msg}
    }

    #检查是否已限制SAM匿名用户连接
    if ($key -eq "MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\Restrictanonymous") {
        $config_line = $value -split ","
        $value = $config_line[1].Trim()
        $msg = if ($value -eq "1") { "已限制SAM匿名用户连接符合标准"} else{"已限制SAM匿名用户连接不符合要求"}
        $msg = $msg + "经授权到用户可以匿名列出账户名,存在社交工程共计或尝试猜测密码到风险."
        $data.project += @{"msg" = $msg}
    }

    #检查是否已限制SAM匿名用户连接2
    if ($key -eq "MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\RestrictanonymousSAM") {
        $config_line = $value -split ","
        $value = $config_line[1].Trim()
        $msg = if ($value -eq "1") { "已限制SAM匿名用户连接2符合标准"} else{"已限制SAM匿名用户连接2不符合要求"}
        $msg = $msg + "经授权到用户可以匿名列出账户名,存在社交工程共计或尝试猜测密码到风险."
        $data.project += @{"msg" = $msg}
    }


}

# 定义一个函数来检查并记录安全策略状态  
function CheckSecurityPolicy($registryKey, $policyName, $condition, $expectedValue, $compliantMessage, $nonCompliantMessage) {  
    $policyStatus = (Get-ItemProperty -Path "Registry::$registryKey" -ErrorAction Stop).$policyName     
    $status = switch ($condition) { 
        '-eq' { if ($policyStatus -eq $expectedValue) { "1" } else { "0" } }
        '-le' { if ($policyStatus -le $expectedValue) { '1' } else { '0' } }  
        '-ge' { if ($policyStatus -ge $expectedValue) { '1' } else { '0' } }  
        default { throw "Unsupported condition: $condition" }  
    }  
    $message = if ($status -eq "1") { $compliantMessage } else { $nonCompliantMessage }  
    $projectData = @{"code" = $status; "msg" = $message}  
    $data['project'] += $projectData  
}  


#检查系统日志文件达到最大大小时的动作的序号
CheckSecurityPolicy 'HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\services\eventlog\System' 'Retention' '-eq' '0' '系统日志文件达到最大大小时的动作的序号符合要求' '系统日志文件达到最大大小时的动作的序号不符合要求'

# 应用日志查看器大小设置  
CheckSecurityPolicy 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Application' 'MaxSize' '-eq' '8192' '应用日志查看器大小设置策略符合标准' '应用日志查看器大小设置策略不符合标准'  
  
#系统日志查看器大小设置
CheckSecurityPolicy 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\System' 'MaxSize' '-eq' '8192' '系统日志查看器大小设置策略符合标准' '系统日志查看器大小设置策略不符合标准'

#安全日志查看器大小设置
CheckSecurityPolicy 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security' 'MaxSize' '-eq' '8192' '安全日志查看器大小设置策略符合标准' '安全日志查看器大小设置策略不符合标准'

#检查是否已开启Windows防火墙
CheckSecurityPolicy 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile' 'EnableFirewall' '-eq' '1' 'Windows防火墙符合标准' 'Windows防火墙不符合要求'

#检查是否已启用SYN攻击保护
CheckSecurityPolicy 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters' 'SynAttackProtect' '-eq' '1' 'SYN攻击保护符合标准' 'SYN攻击保护不符合标准'
#SYN 攻击利用了 TCP/IP 连接建立机制中的安全漏洞.要实施 SYN 洪水攻击,攻击者会使用程序发送大量 TCP SYN 请求来填满服务器上的挂起连接队列

#检查TCP连接请求阈值
CheckSecurityPolicy 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters' 'TcpMaxPortsExhausted' '-eq' '5' 'TCP连接请求阈值符合标准' 'TCP连接请求阈值不符合标准'

#检查取消尝试响应 SYN 请求之前要重新传输 SYN-ACK 的次数
CheckSecurityPolicy 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters' 'TcpMaxConnectResponseRetransmissions' '-eq' '2' '取消尝试响应 SYN 请求之前要重新传输 SYN-ACK 的次数符合标准' '取消尝试响应 SYN 请求之前要重新传输 SYN-ACK 的次数不符合标准'

#检查处于SYN_RCVD 状态下的 TCP 连接阈值
CheckSecurityPolicy 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters' 'TcpMaxHalfOpen' '-eq' '500' '处于SYN_RCVD 状态下的 TCP 连接阈值符合标准' '处于SYN_RCVD 状态下的 TCP 连接阈值不符合标准'

#检查处于SYN_RCVD 状态下,且至少已经进行了一次重新传输的TCP连接阈值
CheckSecurityPolicy 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters' 'TcpMaxHalfOpenRetried' '-eq' '400' '处于SYN_RCVD 状态下,且至少已经进行了一次重新传输的TCP连接阈值符合标准' '处于SYN_RCVD 状态下,且至少已经进行了一次重新传输的TCP连接阈值不符合标准'

#检查是否已启用并正确配置ICMP攻击保护
CheckSecurityPolicy 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters' 'EnableICMPRedirect' '-eq' '0' '检查是否已启用并正确配置ICMP攻击保护符合标准' '检查是否已启用并正确配置ICMP攻击保护不符合标准'

# 检查是否已禁用失效网关检测
CheckSecurityPolicy 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters' 'EnableDeadGWDetect' '-eq' '0' '是否已禁用失效网关检测符合标准' '是否已禁用失效网关检测不符合标准'

# 检查是否已正确配置重传单独数据片段的次数
CheckSecurityPolicy 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters' 'TcpMaxDataRetransmissions' '-eq' '2' '是否已正确配置重传单独数据片段的次数符合标准' '检查是否已正确配置重传单独数据片段的次数不符合标准'

# 检查是否已禁用路由发现功能
CheckSecurityPolicy 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'PerformRouterDiscovery' '-eq' '0' '是否已禁用路由发现功能符合标准' '是否已禁用路由发现功能不符合标准'

# 检查是否已正确配置TCP连接存活时间
CheckSecurityPolicy 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'KeepAliveTime' '-eq' '300000' '是否已正确配置TCP连接存活时间符合标准' '是否已正确配置TCP连接存活时间不符合标准'

# 检查是否已启用并正确配置TCP碎片攻击保护
CheckSecurityPolicy 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'EnablePMTUDiscovery' '-eq' '0' '是否已启用并正确配置TCP碎片攻击保护符合标准' '是否已启用并正确配置TCP碎片攻击保护不符合标准'

# 检查是否已启用"不显示最后的用户名"策略
CheckSecurityPolicy 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'Dontdisplaylastusername' '-eq' '1' '检查是否已启用"不显示最后的用户名"策略符合标准' '检查是否已启用"不显示最后的用户名"策略不符合标准'          

# 检查是否已正确配置"提示用户在密码过期之前进行更改"策略
CheckSecurityPolicy 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'PasswordExpiryWarning' '-eq' '14' '检查是否已正确配置"提示用户在密码过期之前进行更改"策略符合标准' '检查是否已正确配置"提示用户在密码过期之前进行更改"策略不符合标准'

# 检查锁定会话时显示用户信息  
CheckSecurityPolicy 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'DontDisplayLockedUserId' '-eq' '3' '检查是否已正确配置"锁定会话时显示用户信息"策略符合标准' '检查是否已正确配置"锁定会话时显示用户信息"策略不符合标准'  
  
# 检查是否已禁用Windows硬盘默认共享  
CheckSecurityPolicy 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters' 'AutoShareServer' '-eq' '0' '检查是否已禁用Windows硬盘默认共享符合标准' '检查是否已禁用Windows硬盘默认共享不符合标准'  
  
# 检查是否已禁用Windows硬盘默认共享2  
CheckSecurityPolicy 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters' 'AutoShareWks' '-eq' '0' '检查是否已禁用Windows硬盘默认共享2符合标准' '检查是否已禁用Windows硬盘默认共享2不符合标准'

#屏幕自动保护程序
CheckSecurityPolicy 'HKEY_CURRENT_USER\Control Panel\Desktop' 'ScreenSaveActive' '-eq' '1' '屏幕自动保护程序符合标准' '屏幕自动保护程序不符合标准'

#屏幕保护程序启动时间
CheckSecurityPolicy 'HKEY_CURRENT_USER\Control Panel\Desktop' 'ScreenSaveTimeout' '-le' '600' '屏幕保护程序启动时间符合标准' '屏幕保护程序启动时间不符合标准'

#屏幕恢复时使用密码保护
CheckSecurityPolicy 'HKEY_CURRENT_USER\Control Panel\Desktop' 'ScreenSaveTimeOut' '-ge' '1' '屏幕恢复时使用密码保护符合标准' '屏幕恢复时使用密码保护不符合标准'

#是否启用NTP服务同步时钟
CheckSecurityPolicy 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32time\TimeProviders\NtpServer' 'Enabled' '-eq' '1' '启用NTP服务同步时钟策略符合标准' '启用NTP服务同步时钟策略不符合标准'

# 检查关闭默认共享盘  
CheckSecurityPolicy 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa' 'restrictanonymous' '-eq' '1' '关闭默认共享盘策略符合标准' '关闭默认共享盘策略不符合标准'  
  
# 禁止全部驱动器自动播放  
CheckSecurityPolicy 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun' '-eq' '255' '禁止全部驱动器自动播放符合标准' '禁止全部驱动器自动播放不符合标准'  

#检查是否正确配置服务器在暂停会话前所需的空闲时间量
CheckSecurityPolicy 'HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\services\LanmanServer\Parameters' 'Autodisconnect' '-eq' '15' '检查是否正确配置服务器在暂停会话前所需的空闲时间量符合标准' '检查是否正确配置服务器在暂停会话前所需的空闲时间量不符合标准'

# 检查是否已启用"当登录时间用完时自动注销用户"策略
CheckSecurityPolicy 'HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\services\LanmanServer\Parameters' 'Enableforcedlogoff' '-eq' '1' '检查是否已启用"当登录时间用完时自动注销用户"策略符合标准' '检查是否已启用"当登录时间用完时自动注销用户"策略不符合标准'

# 检查是否已禁用"登录时无须按 Ctrl+Alt+Del"策略
CheckSecurityPolicy 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'Disablecad' '-eq' '0' '检查是否已禁用"登录时无须按 Ctrl+Alt+Del"策略符合标准' '检查是否已禁用"登录时无须按 Ctrl+Alt+Del"策略不符合标准'

#检查是否已禁止Windows自动登录
CheckSecurityPolicy 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'AutoAdminLogon' '-eq' '0' '检查是否已禁止Windows自动登录符合标准' '检查是否已禁止Windows自动登录不符合标准'

#域环境：检查是否已正确配置"可被缓存保存的登录的个数"策略
CheckSecurityPolicy 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'CachedLogonsCount' '-eq' '5' '域环境：检查是否已正确配置"可被缓存保存的登录的个数"策略符合标准' '域环境：检查是否已正确配置"可被缓存保存的登录的个数"策略不符合标准'


# 结果处理  
$date = Get-Date  
$filePath = "windowsResult.txt"  
  
# 检查文件是否存在  
if (Test-Path $filePath) {  
    # 文件存在，可以选择覆盖或删除（这里选择覆盖）  
    # 注意：写入操作默认会覆盖文件，所以这里不需要显式删除  
    Write-Host "文件 $filePath 已存在，将覆盖其内容。"  
} else {  
    Write-Host "文件 $filePath 不存在，将创建新文件。"  
}  
  
# 写入或覆盖文件  
# 注意：这里使用 Out-File 并设置 -Encoding utf8 以确保编码正确  
# 并且由于 Out-File 默认行为就是覆盖（如果文件已存在），所以不需要额外逻辑  
$date | Out-File -FilePath $filePath -Encoding utf8 -Append:$false  
  
# 遍历并写入数据到文件  
foreach ($item in $data.project) {  
    Write-Host "{'msg':$($item.msg)}"  
    # 使用 -Append 参数来追加到文件  
    $item.msg | Out-File -FilePath $filePath -Encoding utf8 -Append  
}  


