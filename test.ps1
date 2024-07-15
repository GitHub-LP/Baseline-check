# 设置默认输出文件的编码（如果需要的话）
$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'
$data = @{"project"=@()} 
# 导出安全策略到当前目录
secedit /export /cfg config.cfg /quiet

#账户检查
$userAccounts = Get-WmiObject -Class Win32_UserAccount  
$projectdata = @{"msg"="当前存在账户为：$($userAccounts.Name -join ', ')";}  
$data['project']+=$projectdata			

# 读取安全策略配置文件
$config = Get-Content -path config.cfg
# echo $config

# 遍历配置文件，检查各个策略  
foreach ($line in $config) {  
    $config_line = $line -split "="  
    $key = $config_line[0].Trim()  
    $value = $config_line[1].Trim()  
  
    # 检查guest账户停用策略  
    if ($key -eq "EnableGuestAccount") {  
        $msg = if ($value -eq "1") { "guest账户停用策略符合标准" } else { "guest账户停用策略不符合标准" }  
        $data.project += @{"msg" = $msg}  
    }  
  
    # 检查guest账户重命名策略  
    if ($key -eq "NewGuestName") {  
        $msg = if ($value -eq "Guest") { "guest账户重命名策略不符合标准" } else { "guest账户重命名策略符合标准" }  
        $data.project += @{"msg" = $msg}  
    }  
  
    # 检查密码复杂性策略  
    if ($key -eq "PasswordComplexity") {  
        $msg = if ($value -eq "1") { "密码复杂性策略符合标准" } else { "密码复杂性策略不符合标准" }  
        $data.project += @{"msg" = $msg}  
    }  
    
     #检查密码长度最小值策略
     if ($key -eq "MinimumPasswordLength") {
        $msg = if ($value -eq "8") { "密码最小值策略符合标准"} else { "密码最小值策略不符合标准"}
        $data.project += @{"msg" = $msg}  
     }

     #检查密码最长使用期限策略
     if ($key -eq "MaximumPasswordAge") {
        $msg = if ($value -eq "90") { "密码最长使用期限策略符合标准"} else { "密码最长使用期限策略不符合标准"}
        $data.project += @{"msg" = $msg}  
     }

     #检查账户锁定阀值策略
     if ($key -eq "MinimumPasswordLength") {
        $msg = if ($value -eq "8") { "账户锁定阀值策略符合标准"} else { "账户锁定阀值策略不符合标准"}
        $data.project += @{"msg" = $msg}  
     }
    
}  


#系统日志查看器大小设置
$Key = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\System'
$name = "MaxSize"
$config = (Get-ItemProperty -Path "Registry::$Key" -ErrorAction Stop).$name
if($config -ge "8192")
        {
            $data.code = "1"
            $projectdata = @{"msg"="系统日志查看器大小设置策略符合标准";}
            $data['project']+=$projectdata
        }
        else
        {
            $data.code = "0"
            $projectdata = @{"msg"="系统日志查看器大小设置策略不符合标准";}
            $data['project']+=$projectdata
        }
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


