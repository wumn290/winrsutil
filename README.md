# winrsutil介绍

使用rust编写的Windows系统实用C接口，只依赖std和windows-rs；主要目的是方便自己学习rust练手，积累一些通用代码。


## 如何使用

使用cargo build编译， 在target目录拿到lib和dll， 在C/C++或其它语言代码中调用

## 有哪些功能

目前支持的功能有：
* 获取exe的图标
* 读/写/删除注册表
* 获取WMI命令输出
* 获取文件签名
* 获取文件描述、版权、公司名

未来可能支持的功能有：
* 获取进程/服务列表信息
* 获取网络适配器信息
* 获取设备信息
