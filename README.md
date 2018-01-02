# 主要用途：微信报警和公众号回调接口

## 报警使用：
sendwx.sh是微信发送脚本，此脚本是以zabbix报警格式编写，因此只能用于zabbix的报警使用。

## 微信公众号回调接口使用说明：
* 此功能是方便通过微信进行一些简单的系统操作时使用。
* 安全问题是利用微信回调参数的加密及基于openid的访问控制。
* 利用缩写对照表来对输入进行过滤。
* 发送命令后，分两步：首先会收到命令提交是否成功的回复；然后等命令执行完成后，会有执行结果的回复

## action（脚本）使用说明：利用ansible在目标主机执行或在本地执行。
* 通过ansible执行的action。action查找目录：/data/scripts。微信命令发送方式为：ssh actionname args
* 本地执行的action。action查找目录：/data/scripts/locahost。微信命令发送方式：actionname args
* 由于是通过微信发送命令，因此action的名称和参数尽量简单，便于输入。


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
[action] #访问控制。定义action中定义的动作，允许谁执行
\#svr是脚本名称。
svr= 用户的openid,用户的openid
</pre></code>
