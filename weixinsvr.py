#!/usr/bin/env python
# coding=utf8

import os,os.path
import sys
import getopt
import signal
import time,logging
import logging.handlers
import tornado.httpserver
import tornado.ioloop
import tornado.web
import requests
import hashlib
import json
import ConfigParser
import subprocess
from pwd import getpwnam
from WXBizMsgCrypt import WXBizMsgCrypt
import xml.etree.cElementTree as ET
from multiprocessing import Process,Value
#from ucloud.sdk import UcloudApiClient
from collections import namedtuple
import traceback


Token = {}
Token['time'] = 0
Token['expire'] = 0
DEBUG = 0
ansibleResult = {}

TaskRun = Value('i',0)
MyOption = dict(port = 5005,
                 cookie = 'cliuser',
                 cookie_secret = 'cAjcCxYYiHFpi12YmkghlQUy6yNUkPxqV0MrE9s0g20XTvbaYZrCtm023NlGhMh6',
                 logfile = '/data/log/weixin/weixinsvr.log',
                 run_user = 'nobody',
                 login_expired = 10,
                 pidfile = '/data/log/weixin/weixinsvr.pid',
                 )
logger = logging.getLogger()
loghl = logging.handlers.RotatingFileHandler(MyOption['logfile'], maxBytes=104857600, backupCount=30)
fmt =  logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
loghl.setFormatter(fmt)
logger.addHandler(loghl)
if DEBUG == 0:
    logger.setLevel(logging.INFO)
else:
    logger.setLevel(logging.DEBUG)
    #synclogger.setLevel(logging.DEBUG)
os.environ['USER'] = 'dale'
#logger.info(os.environ)
#通过fork+setuid切换运行身份时，ansible始终认为运行环境是root，造成权限失败。
from ansible.parsing.dataloader import DataLoader
from ansible.vars.manager import VariableManager
from ansible.inventory.manager import InventoryManager
from ansible.playbook.play import Play
from ansible.executor.task_queue_manager import TaskQueueManager
from ansible.plugins.callback import CallbackBase


SvrName = dict(memc = "memcached")
SvrAction = dict(r = "restart", a = "start", o = "stop", l = "reload")

def daemonize (stdin='/dev/null', stdout='/dev/null', stderr='/dev/null', pidfile=None, uid=99):
    ''' Fork the current process as a daemon, redirecting standard file
        descriptors (by default, redirects them to /dev/null).
    '''
    # Perform first fork.
    try:
        pid = os.fork( )
        if pid > 0:
            sys.exit(0) # Exit first parent.
    except OSError, e:
        sys.stderr.write("fork #1 failed: (%d) %s\n" % (e.errno, e.strerror))
        sys.exit(1)
    if pidfile == None:
        pidfile = "/var/run/%s.pid" % sys.argv[0].split('.')[0]
    try:
        pidf = file(pidfile,'w')
        #os.chown(pidfile, uid, uid)
    except IOError,msg:
        logging.warning(msg.strerror)
        sys.exit(1)

    # Decouple from parent environment.
    os.chdir("/")
    os.umask(022)
    os.setsid()
    #os.setuid(uid)
    # Perform second fork.
    try:
        pid = os.fork()
        if pid > 0:
            pidf.write('%d' % pid)
            pidf.close()
            sys.exit(0) # Exit second parent.
    except OSError, e:
        sys.stderr.write("fork #2 failed: (%d) %s\n" % (e.errno, e.strerror))
        sys.exit(1)
    os.setsid()
    # The process is now daemonized, redirect standard file descriptors.
    for f in sys.stdout, sys.stderr: f.flush( )
    si = file(stdin, 'r')
    so = file(stdout, 'a+')
    se = file(stderr, 'a+', 0)
    os.dup2(si.fileno( ), sys.stdin.fileno( ))
    os.dup2(so.fileno( ), sys.stdout.fileno( ))
    os.dup2(se.fileno( ), sys.stderr.fileno( ))

def exit_handler(signum,frame):
    tornado.ioloop.IOLoop.instance().stop()
    #os.remove(MyOption['pidfile'])

class WeiXin():
    def __init__(self,appid,secret):
        self.wxappid = appid
        self.wxsecret = secret

    def get_token(self):
        if self.check_token():
            return Token['cache']

    def check_token(self):
        if time.time() - Token['time'] < Token['expire']:
            return True
        #提前2分钟过期token
        Token['time'] = time.time() - 120
        gettokenurl = "https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=%s&secret=%s"%(self.wxappid,self.wxsecret)
        reps = requests.get(gettokenurl)
        get_token = reps.json()
        Token['cache'] = get_token.get('access_token','NO')
        if Token['cache'] == "NO":
            logging.error("get_token false: %s" % reps.text)
            return False
        Token['expire'] = get_token['expires_in']
        return True
    def send(self,payload):
        if not self.check_token():
            return False
        alteruri = "https://api.weixin.qq.com/cgi-bin/message/template/send?access_token=%s"%Token['cache']
        payloadJson = json.dumps(payload)
        reps = requests.post(alteruri, data=payloadJson)
        result=reps.json()
        if result['errmsg'] != 'ok':
            logging.error("send false: %s" % reps.text)
            return False
        return True
    def get_openid(self,next_openid=None):
        if not self.check_token():
            return ""
        getopenidurl = "https://api.weixin.qq.com/cgi-bin/user/get?access_token=%s"%(token['cache'])
        if next_openid:
            getopenidurl="https://api.weixin.qq.com/cgi-bin/user/get?access_token=%s&next_openid=%s"%(token['cache'],next_openid)
        reps = requests.get(getopenidurl)
        return reps.text

    def get_userinfo(self,openid):
        if not self.check_token():
            return ""
        get_userinfourl = "https://api.weixin.qq.com/cgi-bin/user/info?access_token=%s&openid=%s&lang=zh_CN"%(token['cache'],openid)
        reps = requests.get(get_userinfourl)
        return reps.text

class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/weixin/(send|users|userinfo|token|mon)", WeixinHandler),
            (r"/weixinsvr", WeiXinSvrHandler),
        ]
        settings = dict(
        )
        tornado.web.Application.__init__(self, handlers, **settings)

class WeixinHandler(tornado.web.RequestHandler):
    def get_secure_cookie(self, name, include_name=True, value=None):
        if value is None: value = self.get_cookie(name)
        if not value: return None
        v = value.split('|')
        checkvalue = hashlib.md5("%s|%s" % (MyOption["cookie_secret"],v[1])).hexdigest()
        if v[0] == checkvalue and time.time() - int(v[1]) < MyOption['login_expired']:
            return "admin"
        else:
            logger.warning("%s [signature] %s %s",
                            self.request.headers.get("X_Real_IP", self.request.remote_ip),
                            self.request.headers['Cookie'],
                            self.request.uri,
                            )
            return None

    def get_current_user(self):
        #return True
        return self.get_secure_cookie(MyOption['cookie'])

    def get(self, op):
        if op == "mon":
            self.write("OK")

    def post(self, op):
        if not self.get_current_user():
            self.set_header("Report","No-auth")
            self.set_status(403)
            return
        if op == "send":
            payload = {}
            payload['touser'] = self.get_argument('openid')
            payload['data'] = {}
            payload['data']['first'] = {"value":self.get_argument('title'),"color":"#173177"}
            payload['data']['keyword1'] = {"value":self.get_argument('hostname'),"color":"#173177"}
            payload['data']['keyword2'] = {"value":self.get_argument('date'),"color":"#173177"}
            payload['data']['keyword3'] = {"value":self.get_argument('alrt'),"color":"#173177"}
            payload['data']['remark'] = {"value":self.get_argument('other'),"color":"#173177"}
            payload['url'] = self.get_argument('wei_url', default="")
            payload['topcolor'] = "#FF0000"
            payload['template_id'] = confitem["alerttid"]
            r = weixin.send(payload)
            logger.info("[Alert] touser: %s; eid: %s; msg: %s,%s; wxreply: %s" %
                (payload['touser'],
                payload['url'], payload['data']['first']["value"],
                payload['data']['keyword1']["value"],
                ))
            if not r:
                self.set_status(505)
            self.write("OK\n")
        elif op == "users":
            self.write(weixin.get_openid())
        elif op == "userinfo":
            self.write(weixin.get_userinfo(self.get_argument('openid')))
        elif op == "token":
            self.write(weixin.get_token())

class WeiXinSvrHandler(tornado.web.RequestHandler):
    def get(self):
        echostr = self.get_argument('echostr')
        self.write(echostr)

    def post(self):
        rbody = self.request.body
        msg_signature = self.get_argument('msg_signature')
        encrypt_type = self.get_argument('encrypt_type')
        nonce = self.get_argument('nonce')
        timestamp = self.get_argument('timestamp')
        signature = self.get_argument('signature')
        wxmsg = WXBizMsgCrypt(confitem["token"],
                                confitem["encodingAESKey"],
                                confitem["appid"],
                                )
        ret ,decryp_xml = wxmsg.DecryptMsg(rbody, msg_signature, timestamp, nonce)
        #logger.info("MSG: %s" % decryp_xml)
        xml_tree = ET.fromstring(decryp_xml)
        tname = xml_tree.find("ToUserName")
        fname = xml_tree.find("FromUserName")
        msg_type = xml_tree.find("MsgType")
        msg_content = xml_tree.find("Content")
        msg_reply = "信息错误"
        if msg_type.text == "text":
            msg_info = msg_content.text
            logger.info("from: %s; msgtype: %s; msg: %s" % (fname.text,msg_type.text,msg_info))
            logger.info("TaskRun: %i" % TaskRun.value)
            msg_reply = "正在执行的任务数过多"
            if TaskRun.value < 10:
                msg_reply = "提交成功"
                p = Process(target=subtask, args=(fname.text,msg_info))
                p.start()
        elif msg_type.text == "event":
            eventmsg = xml_tree.find("Event")
            msgid = xml_tree.find("MsgID")
            status = xml_tree.find("Status")
            logger.info("[Event] from: %s; event: %s; msgid: %s; status: %s" %
                (fname.text, eventmsg.text, msgid.text, status.text))
        else:
            logger.info("from: %s; msgtype: %s" % (fname.text,msg_type.text))
        reply = """
<xml>
<ToUserName><![CDATA[%s]]></ToUserName>
<FromUserName><![CDATA[%s]]></FromUserName>
<CreateTime>%i</CreateTime>
<MsgType><![CDATA[text]]></MsgType>
<Content><![CDATA[%s]]></Content>
</xml>
        """ % (fname.text,tname.text,time.time(),msg_reply)
        ret, reply = wxmsg.EncryptMsg(reply,nonce)
        self.write(reply)

def subtask(user,taskinfo):
    TaskRun.value += 1
    tinfo = taskinfo.split()
    """
    任务格式：
    任务名称 任务参数1 任务参数2 ...
    """
    payload = {}
    payload['touser'] = user
    payload['data'] = {}
    payload['data']['first'] = {"value":"执行成功","color":"#173177"}
    payload['data']['keyword1'] = {"value":"微信接口","color":"#173177"}
    payload['data']['keyword2'] = {"value":0,"color":"#173177"}
    indate = time.strftime("%Y/%m/%d %H:%M:%S", time.localtime())
    payload['data']['keyword3'] = {"value":indate,"color":"#173177"}
    payload['data']['remark'] = {"value":"","color":"#173177"}
    payload['url'] = ""
    payload['topcolor'] = "#FF0000"
    payload['template_id'] = confitem["replytid"]
    actionName = tinfo[0]
    actionArgs = tinfo[1:]
    if not checkpermission(user, actionName):
        TaskRun.value -= 1
        return
    logger.info("begin subtask: %s" % tinfo)
    if actionName == "bw":
        response = actionBw(tinfo[1:])
        if response["code"] != 0:
            payload['data']['first']["value"] = "执行失败"
            payload['data']['keyword2']["value"] = response["msg"]
    elif actionName == "ssh":
        response = actionssh(tinfo[1]," ".join(tinfo[2:]))
        if response["code"] != 0:
            payload['data']['first']["value"] = "执行失败"
            payload['data']['keyword2']["value"] = response["code"]
        payload['data']['remark']['value'] = response["msg"]
    elif actionName == "svr":
        shortSvrName = tinfo[1]
        shortSvrAction = tinfo[2]
        svrname = SvrName.get(shortSvrName, shortSvrName)
        svraction = SvrAction.get(shortSvrAction, shortSvrAction)
        if svrname == "memcached":
            result = actionssh('memc', "service %s %s" % (svrname,svraction))
        else:
            result = actioncmd("service %s %s" % (svrname,svraction))
        if result["code"] != 0:
            payload['data']['first']["value"] = "执行失败"
            payload['data']['keyword2']["value"] = result["msg"]
    elif actionName == "cl":
        result = actioncmd("/data/scripts/cl %s %s" % (actionArgs[0],actionArgs[1]))
        if result["code"] != 0:
            payload['data']['first']["value"] = "执行失败"
            payload['data']['keyword2']["value"] = result["code"]
        payload['data']['remark']['value'] = result["msg"]
    elif actionName == "test":
        payload['data']['first']["value"] = "执行成功"
    r = weixin.send(payload)
    if not r:
        logger.error("task failed: %s\n" % taskinfo)
    TaskRun.value -= 1

def checkpermission(user, action):
    if "admin" in confitem:
        if user in confitem["admin"]:
            return True
    if action in confitem:
        if user in confitem[action]:
            return True
    return False


class ResultCallback(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = 'notification'
    CALLBACK_NAME = 'ResultCallback'
    def __init__(self):

        self._play = None
        self._last_task_banner = None
        super(ResultCallback, self).__init__()

    def v2_runner_on_failed(self, result, ignore_errors=False):
        if result._host.name not in ansibleResult:
            ansibleResult[result._host.name] = {}
        ansibleResult[result._host.name] = result._result

    def v2_runner_on_ok(self, result):
        if result._host.name not in ansibleResult:
            ansibleResult[result._host.name] = {}
        logger.info(result._result)
        ansibleResult[result._host.name] = result._result["stdout_lines"]

def ansiblev2(play_source):
    Options = namedtuple('Options', ['connection', 'module_path', 'forks', 'become',
                        'become_method', 'become_user', 'check','diff'])
    # initialize needed objects
    loader = DataLoader()
    options = Options(connection='ssh', module_path='/data/scripts', forks=10,
                become=True, become_method='sudo', become_user='root', check=False,
                diff=False)
    # create inventory and pass to var manager

    inventory = InventoryManager(loader=loader, sources=['/etc/ansible/hosts'])
    variable_manager = VariableManager(loader=loader, inventory=inventory)
    play = Play().load(play_source, variable_manager=variable_manager, loader=loader)

    tqm = None
    results_callback = ResultCallback()
    try:
        tqm = TaskQueueManager(
              inventory=inventory,
              variable_manager=variable_manager,
              loader=loader,
              options=options,
              passwords=None,
              stdout_callback=results_callback,
        )
        result = tqm.run(play)
        return result
    except:
        logger.info(traceback.print_exc())
    finally:
        if tqm is not None:
            tqm.cleanup()

def actionssh(host, cmd):
    play_source = dict(
        hosts = host,
        remote_user = 'dale',
        gather_facts = 'no',
        tasks = [
            dict(name='cmd runing',action=dict(module='script',args='/data/scripts/%s' % cmd))
        ]
    )
    r = dict(RetCode = 0, msg = "OK")
    r["code"]=ansiblev2(play_source)
    if r['code'] != 0:
        logger.error("actionssh host: %s; cmd: %s; result: %d; info: %s" % (host, cmd, r['code'],ansibleResult))
    r['msg'] = json.dumps(ansibleResult,indent=2,ensure_ascii=False)
    #else:
    #    for k,v in ansibleResult.iteritems():
    #        r['msg'] = '%s%s: %s\n' % (r['msg'],k,v)
    return r

def actioncmd(args):
    opipe = subprocess.Popen(args,
                                 shell = True,
                                 stdin = subprocess.PIPE,
                                 stdout = subprocess.PIPE,
                                 stderr = subprocess.PIPE,
                                 )
    out,err = opipe.communicate()
    r = {}
    r["msg"] = out
    r["err"] = err
    r["code"] = opipe.returncode
    return r

def actionBw(str):
    r = dict(code = 0, msg = "OK")
    return r


if __name__ == "__main__":
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hc:")
    except getopt.GetoptError, err:
        print str(err) # will print something like "option -a not recognized"
        sys.exit(2)
    conf = "no"
    for o, a in opts:
        if o == "-h":
            print "%s -c config_file \n" % sys.argv[0]
            sys.exit()
        elif o == '-c':
            conf = os.path.abspath(a)
    daemonize('/dev/null','/data/log/weixin/weixinsvr.out','/data/log/weixin/weixinsvr.err',MyOption['pidfile'])
    config = ConfigParser.ConfigParser()
    config.read(conf)
    # global run_user
    # try:
    #     run_user = config.get('default', 'user')
    # except:
    #     run_user = MyOption['run_user']
    # try:
    #     uid = getpwnam(run_user).pw_uid
    # except:
    #     print "not have user: %s" % run_user
    #     sys.exit(1)
    global weixin, confitem
    confitem = {}
    try:
        secret = config.get('weixincli', 'secret')
        confitem["alerttid"] = config.get('weixincli', 'template_id')
        confitem["token"] = config.get('weixinsvr', 'token')
        confitem["appid"] = config.get('default', 'appid')
        confitem["encodingAESKey"] = config.get('weixinsvr', 'encodingAESKey')
        confitem["replytid"] = config.get('weixinsvr', 'replytid')
    except Exception, e:
        print e
        sys.exit(1)
    try:
        actions = config.items("action")
    except:
        pass
    else:
        for item in actions:
            action =item[0]
            confitem[action] = {}
            for user in item[1].split(","):
                confitem[action][user] = 1
    try:
        admins = config.get('default', 'admin')
    except:
        pass
    else:
        confitem["admin"] = {}
        for admin in admins.split(','):
            confitem["admin"][admin] = "yes"
    #global logger
    signal.signal(signal.SIGTERM,exit_handler)
    signal.signal(signal.SIGQUIT,exit_handler)
    #os.environ['HOME'] = getpwnam(run_user).pw_dir
    #os.environ['USERNAME'] = run_user
    weixin = WeiXin(confitem["appid"],secret)
    http_server = tornado.httpserver.HTTPServer(Application())
    http_server.listen(int(MyOption['port']),'127.0.0.1')
    tornado.ioloop.IOLoop.instance().start()
