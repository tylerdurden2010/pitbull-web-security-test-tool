#!/usr/bin/env python
from libmproxy import controller,proxy
from libmproxy.proxy.server import ProxyServer
from socket import getaddrinfo
import json
import os,re
import zlib
from pymongo import MongoClient
import time

client = MongoClient()
db = client.scanner
Cookies_db = db.Cookies 
All_db = db.AllData
Payload_db = db.Payload

noresult = "(\.jpg|\.gif|\.png|\.css|\.js|\.ico|\.svg|\.woff|\.cur|\.jpge)"
filter = re.compile(noresult,re.IGNORECASE)
nosocketio = re.compile('\/socket\.io\/',re.IGNORECASE)

class Record(controller.Master):
    nametail = 0
    def __init__(self, server):
        controller.Master.__init__(self, server)
        self.stickyhosts = {}

    def run(self):
        try:
            return controller.Master.run(self)
        except KeyboardInterrupt:
            self.shutdown()

    def handle_request(self, flow):
        if( self.Noporxy_request(flow.request.path,flow.request.host) ):
            flow.reply()
        else:
            if (flow.request.headers["Content-Encoding"] == ['gzip']):# and ('json' in flow.request.headers["content-type"]):
                postdata = self.Decode_Request_Body(flow.request.content)
                postdata = postdata.replace("'","\"")
                try:
                    postdata = json.loads(postdata)
                    postdata = self.JsonAnalyze(postdata)
                except Exception,e:
                    print e
            else:
                if (flow.request.headers["content-type"]):
                    postdata = self.SQLPayloadOperate(flow.request.headers["content-type"],flow.request.content,flow.request.get_form_urlencoded())
                else:
                    postdata = None

            if postdata:
                body = str(flow.request.method) + " "+ str(flow.request.path) + " HTTP/1.1\r\n" + str(flow.request.headers) + "\r\n" + str(postdata) + "\r\n"
            else:
                body = str(flow.request.method) + " "+ str(flow.request.path) + " HTTP/1.1\r\n" + str(flow.request.headers) + "\r\n"             
            try:
                IP = getaddrinfo(str(flow.request.host),None)
                IP = str(IP[0][4][0])
            except Exception, e:
                IP = "127.0.0.1"
                print e

    
            self.DBOperation(IP,flow.request.scheme,flow.request.method,flow.request.host,flow.request.path,flow.request.port,flow.request.headers,self.nametail,body,flow.request.content,postdata)

            flow.reply()

    def Record_request(self,content,nametail,hostname,method,path):
        filename = "/tmp/autotest/"+str(Record.nametail)+"."+str(method)+"."+hostname+path.replace('/','_')
        Record.nametail = Record.nametail + 1
        try:
            file = open(filename,"a")
            file.write(content)
            file.flush()
        except IOError,args:
            pass
        file.close()

    def DBOperation(self,ip,scheme,method,host,path,port,headers,nametail,body,content=None,postdata=None):

    #change the  list to  dict
        listheader = list(headers)
        Header = {}
        for i in range(len(listheader)):
            Header[listheader[i][0]] = listheader[i][1]

        AllRequest = {
        "IP":ip,
        "Scheme":str(scheme),
        "Method":str(method),
        "Path":str(path),
        "Port":str(port),
        "Header":Header,
        "Post":str(content),
        "timestamp":int(time.time()),
        }
        #todo 
        #there are some exception on utf 8 string issue, I must solve it soon
        try:
            AllID = All_db.insert_one(AllRequest).inserted_id
            if AllID:
                CookiesData = {
                "All_ID":AllID,
                "Cookie":headers['cookie']
                }

                Cookies_db.insert_one(CookiesData)

                # if (postdata):
                PayloadData = {
                "All_ID" : AllID,
                "Payload" : postdata,
                "Path" : str(self.GETPayloadOperate(str(path))),
                "Host": str(headers['host'][0]),
                "timestamp":int(time.time())

                }
                Payload_db.insert_one(PayloadData) 
        except Exception, e:
            print e

    def GETPayloadOperate(self,path):
        #todo
        newstr = ""
        try:
            rootpath = path.split('?')[0]
            newpath = path.split('?')[1].split('&')
            for item in range(len(newpath)):
                newpath[item] = newpath[item] + "*&"
                newstr = newstr + newpath[item]
            return rootpath+"?"+newstr.rstrip('&')
        except Exception, e:
            return path



    def SQLPayloadOperate(self,contenttype,requestjson,requestpost):
        #jsons = requestjson
        postdata =''
        if 'application/json' in contenttype:
            if isinstance(requestjson,str):
                requestjson = requestjson.replace("'","\"")
                try:
                    requestjson = json.loads(requestjson)
                except Exception,e:
                    print e
                postdata = self.JsonAnalyze(requestjson)
            return postdata
        else:
            form = requestpost
            form = list(form)
            for i in range(len(form)):
                postdata = form[i][0] + "=" + form[i][1] +"*" + "&" + postdata
            postdata = postdata.replace('\n','\\n').strip('&')
            return postdata

    def JsonAnalyze(self,dictparm):
        if isinstance(dictparm,dict):
            for (k,v) in dictparm.items():
                if isinstance(dictparm[k],list) and (dictparm[k]):
                    self.JsonAnalyze(dictparm[k][0])
                else:
                    dictparm[k] = str(dictparm[k]) + '*'
        return str(dictparm)

    def Noporxy_request(self,url,hostname):
        oururl = str(url)
        result = filter.search(url) or nosocketio.search(url) 
        return result

    def Decode_Request_Body(self,data):
        if(not data):
            return ""
        result = zlib.decompress(data,16+zlib.MAX_WBITS)
        return result

config = proxy.ProxyConfig(port=9880)
server = ProxyServer(config)
m = Record(server)
m.run()
