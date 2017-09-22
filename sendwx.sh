#!/bin/bash
#################################
#      微信报警发送脚本
#################################
openid=$1
title=$2
args=$3
hostname=`echo $3 | awk -F\| '{print $1}'`
etime=`echo $3 | awk -F\| '{print $2}'`
itemname=`echo $3 | awk -F\| '{print $3}'`
itemkey=`echo $3 | awk -F\| '{print $4}'`
itemvalue=`echo $3 | awk -F\| '{print $5}'`
turl=`echo $3 | awk -F\| '{print $6}'`

#报警时间
date=$(date +"%Y-%m-%d_%H:%M:%S")

secret="cAjcCxYYiHFpi12YmkghlQUy6yNUkPxqV0MrE9s0g20XTvbaYZrCtm023NlGhMh6"
dd=`date "+%s"`
mm=`echo -n "${secret}|$dd" | md5sum | awk '{print $1}'`
header="Cookie: cliuser=$mm|$dd"
url="http://127.0.0.1/weixin/send"
result=`curl -g --data-urlencode "title=$title" \
--data-urlencode "openid=$openid" \
--data-urlencode "hostname=$hostname" \
--data-urlencode "date=$etime" \
--data-urlencode "alrt=$itemname" \
--data-urlencode "other=$itemkey: $itemvalue" \
--data-urlencode "wei_url=$turl" \
-H "$header" -H "Host: weixin.test.com" -w %{http_code} -o /dev/null $url `
if [ "x$result" == "x200" ]; then
    exit
fi
sleep 3
result=`curl -g --data-urlencode "title=$title" \
--data-urlencode "openid=$openid" \
--data-urlencode "hostname=$hostname" \
--data-urlencode "date=$etime" \
--data-urlencode "alrt=$itemname" \
--data-urlencode "other=$itemkey: $itemvalue" \
--data-urlencode "wei_url=$turl" \
-H "$header" -H "Host: weixin.test.com" -w %{http_code} -o /tmp/weixin.tmp -D /tmp/wxhead.tmp $url`
if [ "x$result" != "x200" ]; then
    date "+%Y%m%d %H:%M:%S" >> /data/logs/weixin/sendwx.log
    echo $data >> /data/logs/weixin/sendwx.log
    cat /tmp/wxhead.tmp >> /data/logs/weixin/sendwx.log
    cat /tmp/weixin.tmp >> /data/logs/weixin/sendwx.log
fi
