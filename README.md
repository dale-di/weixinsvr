# 主要用途：微信报警和公众号回调接口

## 报警使用：
sendwx.sh是微信发送脚本，此脚本是以zabbix报警格式编写，因此只能用于zabbix的报警使用。

## 微信公众号回调接口使用说明：
* 此功能是方便通过微信进行一些简单的系统操作时使用。
* 安全问题是利用微信回调参数的加密及基于openid的访问控制。
* 利用缩写对照表来对输入进行过滤。
* 发送命令后，分两步：首先会收到命令提交是否成功的回复；然后等命令执行完成后，会有执行结果的回复
*


## weixin.conf配置说明：
<pre><code>[default]
appid       = 微信公众号的开发者ID
admin       = 加入公众号后，用户的openid。多给id以逗号分隔
[weixincli]
secret      = 微信公众号的开发者密码
template_id = 微信公众号的模板消息id，用于报警信息使用
[weixinsvr]
token               = 微信公众号号的服务器配置中的“令牌”
encodingAESKey      = 微信公众号号的服务器配置中的“消息加解密密钥”
replytid            = 微信公众号的模板消息id，用于命令执行结果的通知
[actionacl] #访问控制。定义action中定义的动作，允许谁执行
svr= 用户的openid,用户的openid
[action] #定义允许执行的命令
#命令名称=主机名,格式化的命令字符串。args数组是程序定义好的，此处不能更改。
#args的顺序按照微信输入的参数顺序使用。
svr=memc,"service %s %s" % (args[0],args[1])
tt=memc,"ls %s" % (args[0])
[shortkey] # args中的内容缩写对照表，便于微信端输入。
memc=memcached
r=restart
</pre></code>

## 举例说明（以上面的配置为例）：
在微信端输入：svr memc r。实际执行的命令是：service memcached restart。
因为svr对应[action]中的svr配置：host是memc，cmd为"service %s %s" % (args[0],args[1])。
输入的参数memc和r，分别在shortkey中找到对应关系并进行替换：args[0]="memcached",args[1]="restart"
