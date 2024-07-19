@echo off  
echo."====================================================================="
echo."|                                                                   |"
echo."|                 █████╗ ██╗███████╗███╗   ██╗ ██████╗              |"
echo."|                ██╔══██╗██║██╔════╝████╗  ██║██╔════╝              |"
echo."|                ███████║██║█████╗  ██╔██╗ ██║██║  ███╗             |"
echo."|                ██╔══██║██║██╔══╝  ██║╚██╗██║██║   ██║             |"
echo."|                ██║  ██║██║███████╗██║ ╚████║╚██████╔╝             |"
echo."|                ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═══╝ ╚═════╝              |"
echo."|                                   SystemInfoAndIPConfig  v1.0     |"
echo."|                                                by AiENG           |"
echo."====================================================================="

:: 设置输出文件的路径和名称  
set outputFile=SystemInfoAndIPConfig.txt  
  
:: 检查输出文件所在目录是否存在，如果不存在则创建  
:: if not exist "%~dp0Temp\" mkdir "%~dp0Temp"  
  
:: 清除之前可能存在的同名文件  
if exist "%outputFile%" del "%outputFile%"  
  
:: 获取ipconfig信息并追加到文件  
ipconfig > "%outputFile%"  

:: 追加一个空行用于分隔内容  
echo. >> "%outputFile%"  
  
:: 获取systeminfo信息并追加到文件  
systeminfo >> "%outputFile%"  

:: 获取Windows硬件信息
:: 查看CPU
echo. CPU硬件信息: >> "%outputFile%" 
echo. >> "%outputFile%"  
wmic cpu list brief >> "%outputFile%"
:: 查看内存主板数量
echo. 内存主板数量: >> "%outputFile%" 
echo. >> "%outputFile%"  
wmic memorychip list brief >> "%outputFile%"
:: 查看BIOS主板信息
echo. BIOS主板信息: >> "%outputFile%" 
echo. >> "%outputFile%"  
wmic bios get serialnumber >> "%outputFile%"
:: 查看物理内存
:: wmic memphysical list brief >> "%outputFile%"
:: 查看网卡
:: wmic nic list brief >> "%outputFile%"

:: 查看硬盘品牌及大小
:: Wmic logicaldisk >> "%outputFile%"
:: 查看磁盘数量
:: wmic volume >> "%outputFile%"

  
echo.  
echo. 已成功将ipconfig和systeminfo信息以及Windows硬件信息保存到 %outputFile%  
pause