@echo off  
echo."____________________________________________________________________"
echo."|                                                                   |"
echo."|                 █████╗ ██╗███████╗███╗   ██╗ ██████╗              |"
echo."|                ██╔══██╗██║██╔════╝████╗  ██║██╔════╝              |"
echo."|                ███████║██║█████╗  ██╔██╗ ██║██║  ███╗             |"
echo."|                ██╔══██║██║██╔══╝  ██║╚██╗██║██║   ██║             |"
echo."|                ██║  ██║██║███████╗██║ ╚████║╚██████╔╝             |"
echo."|                ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═══╝ ╚═════╝              |"
echo."|                                   SystemInfoAndIPConfig  v1.0     |"
echo."|___________________________________________________________________|"

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


  
echo.  
echo. 已成功将ipconfig和systeminfo信息保存到 %outputFile%  
pause