__author__ = 'Mr.Anderson'
from pymongo import MongoClient
import codecs
import os,requests
from bson.objectid import ObjectId
import json
from time import sleep,time
import zmq
import threading
from hashlib import md5 
#XssAttack
#CSRFattack
class DBOpreate(object):
    def __init__(self):
        client = MongoClient()
        self.db = client.scanner
    def ReadDBOne(self,dbname,DBID=None):
        if dbname == "0":
            try:
                result = self.db.SQLAttack.find_one({"_id":ObjectId(DBID)})
            except Exception,e:
                print e
                result = None
        elif dbname == "1":
            try:
                result = self.db.XSSAttack.find_one({"_id":ObjectId(DBID)})
            except Exception,e:
                print e
                result = None
        elif dbname =="2":
            try:
                result = self.db.CSRFAttack.find_one({"_id":ObjectId(DBID)})
            except Exception,e:
                print e
                result = None
        else:
            result = None

        return result

    def ReadSQLAttackDBOne(self,DBID=None):
        try:
            result = self.db.SQLAttack.find_one({"_id":ObjectId(DBID)})
        except Exception,e:
            print e
            result = None
        return result
    def ReadAllDataDBOne(self,DBID=None):
        try:
            result = self.db.AllData.find_one({"_id":ObjectId(DBID)})
        except Exception,e:
            print e
            result = None
        return result

    def WriteDB(self):
        pass

    def UpdateDB(self,DBID,dbname,result):
        if dbname == "0":
            try:
                final = self.db.SQLAttack.update({'_id':ObjectId(DBID)},{"$set":result},upsert=False)
            except Exception,e:
                print e
                final = None
        elif dbname == "1":
            #So far, the xss attack result updated by casperjs
            try:
                final = self.db.XSSAttack.update({'_id':ObjectId(DBID)},{"$set":result},upsert=False)
            except Exception,e:
                print e
                final = None
        elif dbname =="2":
            try:
                final = self.db.CSRFAttack.update({'_id':ObjectId(DBID)},{"$set":result},upsert=False)
            except Exception,e:
                print e
                final = None
        else:
            final = None


    def DeleteDB(self):
        pass

    #this class is using for generate the payload file
    #So far , I have to write files to /tmp/autotest
    #The purpose of write files is that sqlmap.py -r
    #the values of return are array.
    #The Request is from database
    #DBOpreate class, ReadDBOne function return the json foramate

class InjectionRequest(object):
    count = 0
    def __init__(self):
        InjectionRequest.count = InjectionRequest.count+1
        if os.path.exists('/tmp/autotest/'):
            pass
        else:
            os.mkdir('/tmp/autotest/')

    def WriteFile(self,Request):
        Path = Request['Path'].replace("/","_").replace('*','_')
        if (len(Path) > 128):
            Path = Path[:128]

        FileName = str(InjectionRequest.count)+"."+Request['Method'] + "."+Request['Header']['Host']+"."+Path+ str(time())
    	AttackInfo = []
        try:
	    #Solution:http://stackoverflow.com/questions/19591458/python-reading-from-a-file-and-saving-to-utf-8
            FileHandle = codecs.open('/tmp/autotest/'+FileName,"w",'utf-8')
            content = Request['Method'] + " "+Request['Path'] + " " + "HTTP/1.1\r\n"
            for key in Request['Header']:
                content = content + key + ":" +" "+Request['Header'][key] + "\r\n"
            if(Request['Payload']):
                content = content +"\r\n"+ Request['Payload'] + "\r\n"
            else:
                content = content +"\r\n"
            FileHandle.write(content)
            FileHandle.flush()
	    FileHandle.close()
        except Exception,e:
            print e
            return None

        if(Request['Scheme'] == 'http'):
            AttackInfo.append(FileName)
            AttackInfo.append('http')
            AttackInfo.append(Request['Level'])
            AttackInfo.append(Request['Dbms'])
        else:
            AttackInfo.append(FileName)
            AttackInfo.append('https')
            AttackInfo.append(Request['Level'])
            AttackInfo.append(Request['Dbms'])

        return AttackInfo

        #filehandle = os.open()

#About requests
#http://cn.python-requests.org/zh_CN/latest/user/quickstart.html#id2
class SQLMAPOpreate(object):
    def __init__(self):
        self.url = "http://127.0.0.1:8033"

    def Connection(self):
        try:
            r = requests.get(self.url+'/task/new')
        except Exception,e:
            print e
            r = {"":""}
            return None
        return r.json()

    #this function is using for post {"requestFile":xxx,""} to /options/taskid/set
    #it's seem to configuration
    #todo the next step is doing some gzip func
    def ParamSetting(self,taskid,params):
        headers = {'content-type':'application/json'}
        url = self.url+'/option/'+taskid +'/set'
        params[0] ='/tmp/autotest/'+ params[0]
        if(params[1] == 'https'):
            payload={"requestFile":params[0],"forceSSL":True,"level":int(params[2]),"dbms":params[3]}
        else:
            payload={"requestFile":params[0],"level":int(params[2]),"dbms":params[3]}
        r = requests.post(url,data=json.dumps(payload),headers=headers)
        checkurl = self.url + '/option/' + taskid +'/list'
        return requests.get(checkurl).json()

    #start the sqlmapapi
    def Starting(self,taskid):
        headers = {'content-type':'application/json'}
        starturl = self.url+ '/scan/' + taskid +'/start'
        payload = {'url':''}
        return requests.post(starturl,data=json.dumps(payload),headers=headers).json()
    #show the current status
    def Status(self,taskid):
        statusurl = self.url + '/scan/' + taskid + '/status'
        return requests.get(statusurl).json()

    def ScanLog(self,taskid):
        logurl = self.url+'/scan/' + taskid +'/log'
        return requests.get(logurl).json()


def sqlmapAPI(DBresult):
    #dbtest = DBOpreate()
    inject = InjectionRequest()
    #info told sqlmapapi the location of payload
    Info = inject.WriteFile(DBresult)
    sqlattack = SQLMAPOpreate()
    #connect to sqlmapapi and return the taskid which generated by sqlmapapi
    sqlrequest = sqlattack.Connection()
    taskid = sqlrequest['taskid']
    if(taskid):
        print Info
        sqlresult = sqlattack.ParamSetting(taskid,Info)
        if (sqlresult['success']):
           test = sqlattack.Starting(taskid)
        if test['success']:
           statusresult = sqlattack.Status(taskid)
           while(statusresult['status'] != "terminated"):
               statusresult = sqlattack.Status(taskid)
               sleep(5)
               result = sqlattack.ScanLog(taskid)
               result = {"Result":result,"Timestamp":int(time())}
               attackRecord.UpdateDB(DBID,"0",result)
           result = sqlattack.ScanLog(taskid)
           result = {"Result":result,"Timestamp":int(time())}
           attackRecord.UpdateDB(DBID,"0",result)

def XSSTest(DBresult):
    if DBresult['Port'] == "80" or DBresult['Port'] == "443":
        URL = DBresult['Scheme']+"://"+DBresult['Header']['Host']+DBresult['Path']
    else:
        URL = DBresult['Scheme']+"://"+DBresult['Header']['Host'] + ":"+ DBresult['Port']+DBresult['Path']
    XSSID = '--ID=' + '"' + str(DBresult['_id']) +'"'
    pitserver = '--pitserver="http://127.0.0.1:3000/xssresultsave"'
    if "Cookie" in DBresult['Header']:
        Cookie = " --cookie=" + "'" +DBresult['Header']['Cookie'] +"'"
        #Cookie = ' --cookie=' + DBresult['Header']['Cookie']
    else:
        Cookie = ''
    #--pitserver="http://192.168.21.201:3000/xsssave" --originid="55e23211a43ea8e435b72231"
    cmd = "casperjs newxss.js -u "+ '"' + URL +'"' +" "+pitserver+" "+XSSID + Cookie
    
    if DBresult['Method'] == "GET":
        result = os.popen(cmd).readlines()
        result = {"Result":result,"Timestamp":int(time())}
        attackRecord.UpdateDB(DBID,"1",result)
        
    elif DBresult['Payload']:
        postdata = " --postdata=" +"'" + DBresult['Payload'] + "'"
        cmd = cmd + postdata

        print cmd
        result = os.popen(cmd).readlines()
        result = {"Result":result,"Timestamp":int(time())}
        attackRecord.UpdateDB(DBID,"1",result)


def CSRFTest(DBresult):
    if DBresult['Port'] == "80" or DBresult['Port'] == "443":
        URL = DBresult['Scheme']+"://"+DBresult['Header']['Host']+DBresult['Path']
    else:
        URL = DBresult['Scheme']+"://"+DBresult['Header']['Host'] + ":"+ DBresult['Port']+DBresult['Path']
    RefererHeader = DBresult['Header']['Referer']
    CookieHeader = DBresult['Header']['Cookie']
    # NoRefere = DBresult['Header'].pop("Refere",None)
    # NoCookie = DBresult['Header'].pop("Cookie",None)
    #print OriginHeader

    if DBresult['Method'] == "GET":
        Result = {}
        originResponse = requests.get(URL,headers = DBresult['Header'])
        Result.setdefault("Origin",md5(originResponse.text.encode('utf-8')).hexdigest())
        NoReferer = DBresult['Header'].pop("Referer",None)
        NoRefereResponse = requests.get(URL,headers = DBresult['Header'])
        Result.setdefault("NoReferer",md5(NoRefereResponse.text.encode('utf-8')).hexdigest())
        DBresult['Header'].setdefault("Referer",RefererHeader)
        DBresult['Header'].pop("Cookie",None)
        NoCookieResponse = requests.get(URL,headers = DBresult['Header'])
        Result.setdefault("NoCookie",md5(NoCookieResponse.text.encode('utf-8')).hexdigest())
        #print Result
        result = {"Result":Result,"Timestamp":int(time())}
        attackRecord.UpdateDB(DBID,"2",result)
        #DBresult['Header'].setdefault("Cookie",CookieHeader)
        #print md5(originResponse.text.encode('utf-8')).hexdigest()
        #print md5(rep).hexdigest()

        
        
    else:
        Result = {}
        originResponse = requests.post(URL,data = json.dumps(DBresult['Payload']),headers = DBresult['Header'])
        Result.setdefault("Origin",md5(originResponse.text.encode('utf-8')).hexdigest())
        DBresult['Header'].pop("Referer",None)
        NoRefereResponse = requests.post(URL,data = json.dumps(DBresult['Payload']),headers = DBresult['Header'])
        Result.setdefault("NoReferer",md5(NoRefereResponse.text.encode('utf-8')).hexdigest())
        DBresult['Header'].setdefault("Referer",RefererHeader)
        DBresult['Header'].pop("Cookie",None)
        NoCookieResponse = requests.post(URL,data = json.dumps(DBresult['Payload']),headers = DBresult['Header'])
        Result.setdefault("NoCookie",md5(NoCookieResponse.text.encode('utf-8')).hexdigest())
        DBresult['Header'].setdefault("Cookie",CookieHeader)
        #print Result
        result = {"Result":Result,"Timestamp":int(time())}
        attackRecord.UpdateDB(DBID,"2",result)

        #print md5.new(r.text).hexdigest()
    


if __name__ == '__main__':

    context = zmq.Context()
    socket = context.socket(zmq.PAIR)
    socket.bind("tcp://*:5555")
    attackRecord = DBOpreate()

    sleep(1)
    while 1:
        #the DBID is sqlattack database ID
        info = socket.recv()
        DBID = info.split(':')[0]
        dbname_number = info.split(':')[1]
        DBresult = attackRecord.ReadDBOne(dbname_number,DBID)
        if dbname_number == "0":
            newSQL = threading.Thread(target=sqlmapAPI,args=(DBresult,))
            newSQL.start()
        elif dbname_number == "1":
            newXSS = threading.Thread(target=XSSTest,args=(DBresult,))
            newXSS.start()
        elif dbname_number == "2":
            newCSRF = threading.Thread(target=CSRFTest,args=(DBresult,))
            newCSRF.start()
            pass

        else :
            print "Attack type error"
        #result = attackRecord.ReadDBOne(dbname_number,DBID)

        # SQLAttackDBresult = dbtest.ReadSQLAttackDBOne(DBID)
        
        # #test = dbtest.ReadAllDataDBOne( SQLAttackDBresult['OriginID'] )
        
        # newT = threading.Thread(target=sqlmapAPI,args=(SQLAttackDBresult,))
        # newT.start()




