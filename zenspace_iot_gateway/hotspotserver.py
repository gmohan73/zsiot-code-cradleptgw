import cgi
import json
import time
import urllib.request
import datetime
import sys
# from http.server import HTTPServer, SimpleHTTPRequestHandler
from server import HTTPServer, SimpleHTTPRequestHandler
from threading import Thread
from threading import Timer
from time import sleep
import cs
from app_logging import AppLogger
import re
import settings
log= AppLogger()
global record
record = {}
admin_pin={}
validverify=''
headers={};
aheaders={}
url="http://192.168.100.1:9001"
headers = {"Content-Type": "application/json"}
aheaders= {"Content-Type":"application/x-www-form-urlencoded"}
activeClients=0
TIMER = 10
URL_TIMEOUT = 40
REVOKE_UNAUTH_TIMER=60
totalClients=settings.HOTSPOT_CLIENTS
hotspot_url=settings.HOTSPOT_URL
hotspot_method=settings.HOTSPOT_METHOD
#windows_firewallstate=settings.WINDOWS_FIREWALL

podId__j=cs.CSClient().get('/config/system/system_id')
if podId__j != None:
    pod_id=podId__j.get("data")

#Starting server http://{}:9001.This server will run forever
def start_server():
    # avoid 8080, as the router may have service on it.
    # Firewall rules will need to be changed in the router
    # to allow access on this port.
    server_address = ('', 9002)

    print('Starting Server: {}'.format(server_address))
    log.info('Starting Server: {}'.format(server_address))

    log.info('Zenspace hotspot server started');




    try:
        httpd = HTTPServer(server_address, WebServerRequestHandler)
        httpd.serve_forever()

    except Exception as e:
        print('Stopping Server, Key Board interrupt')
        log.debug("Exception raised in 9002 server {}".format(e))


    return 0

def code_verify():
    try:
        dat = {"type": "INFO", "deviceType": "cradlepoint", "name": "Hotspot",
               "message": {"status": "Hotspot integrated code installed"}}
        data = json.dumps(dat).encode("utf-8")
        req = urllib.request.Request(url + "/eventhub", headers=headers, data=data, method="PUT")
        resp = urllib.request.urlopen(req, timeout=URL_TIMEOUT)
    except Exception as e:
        log.debug("Exception raised in code_verify {}".format(e))
def inform_windows_add(client_ip):
    global windows_firewallstate
    log.debug("in inform windows add")
    print("inform windows add")
    internalHost="0.0.0.0"
    try:
        mac_list = cs.CSClient().get('/config/dhcpd/reserve').get('data')
        log.debug("mac list is {}".format(mac_list))
        if (mac_list != None):
            if (len(mac_list) > 0):

                for item in mac_list:
                    host = item["ip_address"]
                    hostname = item["hostname"]
                    if hostname.upper().__contains__("WIN"):
                        internalHost = host
                        log.debug("host name found")

        try:
            req = urllib.request.Request("http://" +internalHost+ ":9004/firewallrule/"+client_ip, headers=headers, method="PUT")

            resp = urllib.request.urlopen(req, timeout=URL_TIMEOUT)
            log.debug("resp code- {}".format(resp.read()))
        except Exception as e:
            print("Exception {}".format(e))
            #log.debug("Exception raises on calling windows server = {} , client ip is {}".format(e,client_ip))
            try:

                    dat = {"type": "WARNING", "deviceType": "Windows", "name": "Windows server", "message": {"status":"Inform to windows about the ip = {} fails.Error is  {} ".format(client_ip,e)}}
                    log.debug(dat)
                    data=json.dumps(dat).encode("utf-8")
                    req = urllib.request.Request(url+"/eventhub", headers=headers, data = data,method="PUT")
                    resp = urllib.request.urlopen(req, timeout=URL_TIMEOUT)
                    log.debug("response is {}".format(resp))
            except Exception as e:
                log.error("Exception raises on raising ticket about informing windows to add rule {} , client ip is".format(e,client_ip))


    except Exception as e:
        print("Exception {}".format(e))
        #log.error("Exception raised while informing windows to add rule {} , client ip = ".format(e,client_ip))
        try:

                dat = {"type": "WARNING", "deviceType": "Windows", "name": "Windows server",
                       "message": {"status": "Inform to windows about the ip = {} fails.Error is  {} ".format(client_ip, e)}}
                log.debug(dat)
                data = json.dumps(dat).encode("utf-8")
                req = urllib.request.Request(url + "/eventhub", headers=headers, data=data, method="PUT")
                resp = urllib.request.urlopen(req, timeout=URL_TIMEOUT)
        except Exception as e:
            log.error("Exception raises on raising ticket about informing windows {} , client ip is {}".format(e,client_ip))

def inform_windows_delete(client_ip):
    global windows_firewallstate
    internalHost="0.0.0.0"
    try:
        mac_list = cs.CSClient().get('/config/dhcpd/reserve').get('data')
        if (mac_list != None):
            if (len(mac_list) > 0):

                for item in mac_list:
                    host = item["ip_address"]
                    hostname = item["hostname"]
                    if hostname.upper().__contains__("WIN"):
                        internalHost = host
        try:
            req = urllib.request.Request("http://" +internalHost+ ":9004/delfirewall/"+client_ip, headers=headers, method="PUT")
            resp = urllib.request.urlopen(req, timeout=URL_TIMEOUT)
            log.debug("resp code- {}".format(resp.read()))
        except Exception as e:
            #log.debug("Exception raises on calling windows server = {},client ip is {}".format(e,client_ip))
            try:
                dat = {"type": "WARNING", "deviceType": "Windows", "name": "Windows server", "message": {"status":"Inform to windows about the ip = {} fails.Error is  {} ".format(client_ip,e)}}
                log.debug(dat)
                data=json.dumps(dat).encode("utf-8")
                req = urllib.request.Request(url+"/eventhub", headers=headers, data = data,method="PUT")
                resp = urllib.request.urlopen(req, timeout=URL_TIMEOUT)
            except Exception as e:
                log.error("Exception raises on raising ticket about informing windows to delete rule of {} -- {}".format(client_ip,e))


    except Exception as e:
        #log.error("Exception raised while informing windows to delete rule {},client ip = {}".format(e,client_ip))
        try:
            dat = {"type": "WARNING", "deviceType": "Windows", "name": "Windows server",
                   "message": {"status": "Inform to windows about the ip = {} fails.Error is  {} ".format(client_ip, e)}}
            log.debug(dat)
            data = json.dumps(dat).encode("utf-8")
            req = urllib.request.Request(url + "/eventhub", headers=headers, data=data, method="PUT")
            resp = urllib.request.urlopen(req, timeout=URL_TIMEOUT)
        except Exception as e:
            log.error("Exception raises on raising ticket about informing windows to delete rule , client ip is {} , exception is {}".format(client_ip,e))

#
# def windows_firewall():
#     global windows_firewallstate
#     try:
#
#         firewall_state=cs.CSClient().get("/zenspace/windows_firewall").get("data")
#         print(firewall_state)
#         if firewall_state != None:
#             windows_firewallstate=firewall_state
#
#
#     except Exception as e:
#         log.debug("Exception raised in windows_firewall = {}".format(e))

def active_hotspot_clients():
    global activeClients
    try:
        total_hotspot_clients()
        clientsList=cs.CSClient().get("/status/hotspot/clients").get("data")
        print(clientsList)
        if clientsList != None:
            activeClients=len(clientsList)
        else:
            activeClients=0
    except Exception as e:
        log.debug("Exception raised in active_hotspot_clients = {}".format(e))

def total_hotspot_clients():
    global totalClients
    try:
        tClients=cs.CSClient().get("zenspace/hotspot_clients").get("data")
        if tClients != None:
            totalClients=tClients
    except Exception as e:
        log.debug("Exception raised in total_hotspot_clients = {}".format(e))

def hotspot_authentication_method():
    global hotspot_method
    try:
        thmethod=cs.CSClient().get("zenspace/hotspot_method").get("data")
        if thmethod != None:
            hotspot_method=thmethod
    except Exception as e:
        log.debug("Exception raised in hotspot method {}".format(e))

def verifyAuth(pin,client_ip):
    global iot_ip,totalClients,activeClients,hotspot_method,admin_pin,aheaders,windows_firewallstate
    print("hotspot method {}".format(hotspot_method))
    log.debug("hotspot method is {}".format(hotspot_method))
    hotspot_authentication_method()
    if hotspot_method == "remote":
        log.debug("hotspot method is remote")

        localdate = datetime.datetime.now().date()
        print("pod_id {}".format(pod_id))
        dat = {"key": pin, "physicalpod": pod_id, "localdate": localdate}
        data = urllib.parse.urlencode(dat).encode('utf-8')
        try:
            req = urllib.request.Request(hotspot_url, headers=aheaders, data=data, method="POST")
            resp = urllib.request.urlopen(req)
            print(resp.status)
            status = resp.status
            result = json.loads(resp.read()).get("result")


            if status == 202:
                print("admin")
                for res in result:
                    if "user_key__c" in res.keys() and "admin_pin__c" in res.keys():
                        user_key = res.get("user_key__c")
                        apin =res.get("admin_pin__c")
                        admin_pin.update({user_key : apin})
                        return 202
                    else:
                        print("retun fail")
                        return 1

            elif status == 200:
                print("user")
                end_time = []
                for res in result:
                    print(res)
                    if "reservation_start_datetime__c" in res.keys() and "reservation_end_datetime__c" in res.keys():
                        curtime = datetime.datetime.utcnow()
                        start_time = datetime.datetime.strptime(res.get("reservation_start_datetime__c"), "%Y-%m-%dT%H:%M:%S")

                        print(start_time)
                        if start_time <= curtime:
                            end_time.append(
                                str(datetime.datetime.strptime(res.get("reservation_end_datetime__c"), "%Y-%m-%dT%H:%M:%S")))

                print("end_time :: {}".format(end_time))
                revoke_end_time=max(end_time);
                print("sort end time {}".format(max(end_time)))
                active_hotspot_clients()
                log.debug("total clients - {} , active clients - {}".format(totalClients,activeClients))
                if activeClients < totalClients:
                    log.debug("calling windows add")
                    # windows_firewall()
                    # log.debug(" Firewall state is -{}".format(windows_firewallstate))
                    # if windows_firewallstate == "enabled":
                    #     setTimeout(0,inform_windows_add,client_ip)
                    record.update({client_ip: [start_time,max(end_time), pin]})
                    try:
                        dat={"timeOut":str(max(end_time))}
                        data = json.dumps(dat).encode("utf-8")
                        req = urllib.request.Request(url+ "/reservationHotspotLogin", headers=headers, data=data,method="POST")
                        resp = urllib.request.urlopen(req, timeout=URL_TIMEOUT)
                        log.debug("resp code- {}".format(resp.read()))
                    except Exception as e:
                        log.debug("Exception raises on calling /reservationHotspotLogin = {}".format(e))
                    return 0
                else:
                    return 2


            else:
                print("no active admin and reservations found")
                return 1
        except Exception as e:
            print("Exception raised in verifyAuth  {}".format(e))
            return 1
    else:
            log.debug("hotspot method is {}".format(hotspot_method))
            try:
                auth = cs.CSClient().get("zenspace/pin_auth");
                admin_auth=cs.CSClient().get("zenspace/admin_auth")
                auth_list = auth.get("data");
                admin_auth_list=admin_auth.get("data")
                print("admin auth list {}".format(admin_auth_list))
                totalpincount = 0

                if auth_list != None:

                    availablePins = {};
                    totalPins = [];
                    plist = [];
                    pinlist = [];
                    avpins = [];
                    for pins in auth_list:
                        availablePins.update(pins)
                    for i, j in availablePins.items():
                        plist = [];
                        avpins.append(j.get("pin"))
                        plist.append(j.get("pin"))
                        plist.append(i)
                        plist.append(j.get("TimeOut"))
                        pinlist.append(plist)

                    totalpincount = avpins.__len__()
                    if pin in avpins:
                        validverify = ''
                        for k in pinlist:
                            if pin in k[0]:
                                timeIn = datetime.datetime.strptime(k[1], "%Y-%m-%d%H:%M:%S")
                                timeOut = datetime.datetime.strptime(k[2], "%Y-%m-%d%H:%M:%S")

                                curtime = datetime.datetime.utcnow()
                                if (timeIn <= curtime and curtime <= timeOut):
                                    validverify = "valid"
                                    tout=str(timeOut)
                                    timeout=datetime.datetime.strptime(tout, "%Y-%m-%d %H:%M:%S")
                                    active_hotspot_clients()
                                    log.debug("total clients - {} , active clients - {}".format(totalClients,activeClients))
                                    if activeClients < totalClients:
                                        # windows_firewall()
                                        # log.debug(" Firewall state is -{}".format(windows_firewallstate))
                                        # if windows_firewallstate == "enabled":
                                        #     setTimeout(0, inform_windows_add, client_ip)
                                        record.update({client_ip: [timeIn,timeout , pin]})
                                        try:
                                            dat={"timeOut":str(timeout)}
                                            data = json.dumps(dat).encode("utf-8")
                                            req = urllib.request.Request(url+ "/reservationHotspotLogin", headers=headers, data=data,
                                                                         method="POST")
                                            resp = urllib.request.urlopen(req, timeout=URL_TIMEOUT)
                                            log.debug("resp code- {}".format(resp.read()))
                                        except Exception as e:
                                                log.debug("Exception raises on calling /reservationHotspotLogin = {}".format(e))
                                        return 0
                                    else:
                                            return 2
                                else:
                                    validverify = "invalid"
                        if validverify == "invalid":
                            if admin_auth_list != None:
                                availableadminPins = {};
                                for i in admin_auth_list:
                                    availableadminPins.update(i)
                                if pin in availableadminPins.keys():

                                    return 202
                                else:

                                    return 1
                            else:
                                return 1




                    else:

                            if admin_auth_list != None:
                                availableadminPins = {};
                                for i in admin_auth_list:
                                    availableadminPins.update(i)

                                if pin in availableadminPins.keys():

                                    return 202
                                else:
                                    log.debug("Accessing pin is not present")
                                    return 1
                            else:
                                return 1



                else:

                        #return getAuthentications(pin,totalpincount)
                        if admin_auth_list != None:
                          availableadminPins = {};
                          for i in admin_auth_list:
                                availableadminPins.update(i)

                          if pin in availableadminPins.keys():

                              return 202
                          else:

                              log.debug("Accessing pin is not present")
                              return 1
                        else:
                             return 1
            except Exception as e:
                log.debug("Exception raised in verify Auth {}".format(e))
                return 1




#Server handler
#For Post request-PIN send by the client is validated and return the response as per rule
#IP of client,expiry time is updated to the global record when post request happens
class WebServerRequestHandler(SimpleHTTPRequestHandler):
    print('handler')
    global validverify

    def do_GET(self):
        log.debug(" Inside Hotspot server get request")
        path = self.path
        log.debug(" PAth is -{}".format(path))
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-control-Allow-Origin', '*')
        self.send_header('Acess-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers',
                         'Content-Type, X-Requested-with')
        self.end_headers()
    def do_POST(self):
        global activeClients,totalClients
        log.debug("POST request")
        log.debug(" Inside Hotspot server get request")
        path = self.path
        log.debug(" PAth is -{}".format(path))

        if None != re.search('/doorLock', self.path):

            log.debug("/door post request")
            sensorName = self.path.split('/')[-1]
            log.debug(".....{}".format(sensorName))
            log.debug("headers..{}".format(self.headers))


            try:
                content_length = int(self.headers['Content-Length'])

                log.debug("content length is {}".format(content_length))
                body = self.rfile.read(content_length)
                log.debug("request body - {}".format(body))

                data = json.loads(body)

                for x, y in data.items():

                    if x == "pin":
                        client_ip=self.client_address[0]
                        s = verifyAuth(y,client_ip)

                        if s == 0:

                            self.send_response(200)
                            self.send_header('Content-type', 'application/json')
                            self.send_header('Access-control-Allow-Origin', '*')
                            self.send_header('Acess-Control-Allow-Methods', 'GET, POST, OPTIONS')
                            self.send_header('Access-Control-Allow-Headers',
                                             'Content-Type, X-Requested-with')
                            self.end_headers()
                            self.wfile.write(bytes(json.dumps({"success": "true"}), 'utf-8'))




                        elif s == 1:
                            self.send_response(401)
                            self.send_header('Content-type', 'application/json')
                            self.send_header('Access-control-Allow-Origin', '*')
                            self.send_header('Acess-Control-Allow-Methods', 'GET, POST, OPTIONS')
                            self.send_header('Access-Control-Allow-Headers',
                                             'Content-Type, X-Requested-with')
                            self.end_headers()
                            self.wfile.write(bytes(json.dumps({"success": "false"}), 'utf-8'))

                        elif s == 202:
                            self.send_response(202)
                            self.send_header('Content-type', 'application/json')
                            self.send_header('Access-control-Allow-Origin', '*')
                            self.send_header('Acess-Control-Allow-Methods', 'GET, POST, OPTIONS')
                            self.send_header('Access-Control-Allow-Headers',
                                             'Content-Type, X-Requested-with')

                            self.end_headers()
                            self.wfile.write(bytes(json.dumps({"success": "ok"}), 'utf-8'))
                        elif s ==2:
                            self.send_response(200)
                            self.send_header('Content-type', 'application/json')
                            self.send_header('Access-control-Allow-Origin', '*')
                            self.send_header('Acess-Control-Allow-Methods', 'GET, POST, OPTIONS')
                            self.send_header('Access-Control-Allow-Headers',
                                             'Content-Type, X-Requested-with')

                            self.end_headers()
                            self.wfile.write(bytes(json.dumps({"success": "exceed"}), 'utf-8'))

                        else:
                            self.send_response(500)
                            self.send_header('Content-type', 'application/json')
                            self.send_header('Access-control-Allow-Origin', '*')
                            self.send_header('Acess-Control-Allow-Methods', 'GET, POST, OPTIONS')
                            self.send_header('Access-Control-Allow-Headers',
                                             'Content-Type, X-Requested-with')

                            self.end_headers()
                            self.wfile.write(b'Unexpected error')


                    else:
                        self.send_response(403)
                        self.send_header('Content-type', 'application/json')
                        self.send_header('Access-control-Allow-Origin', '*')
                        self.send_header('Acess-Control-Allow-Methods', 'GET, POST, OPTIONS')
                        self.send_header('Access-Control-Allow-Headers',
                                         'Content-Type, X-Requested-with')

                        self.end_headers()
                        self.wfile.write(b'BAD Request')

            except Exception as e:
                log.debug("Exception raised in /doorLock post request {}".format(e))
                self.send_response(412)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-control-Allow-Origin', '*')
                self.send_header('Acess-Control-Allow-Methods', 'GET, POST, OPTIONS')
                self.send_header('Access-Control-Allow-Headers',
                                 'Content-Type, X-Requested-with')

                self.end_headers()
                self.wfile.write(b'BAD Request')


        elif None != re.search('/admindoorLock', self.path):

            log.debug("/admindoorLock post request")

            type = self.headers['Content-Type']

            try:
                content_length = int(self.headers['Content-Length'])

                log.debug("content length is {}".format(content_length))
                body = self.rfile.read(content_length)
                log.debug("request body - {}".format(body))

                data = json.loads(body)
                if "adminpin" in data.keys() and "adminkey" in data.keys() and "duration" in data.keys():
                    adminPin = data.get("adminpin")
                    adminkey = data.get("adminkey")
                    duration=data.get("duration")
                    hotspot_authentication_method()
                    if hotspot_method == "remote":
                        print("\n\n\n {}".format(admin_pin))
                        print("\nadminkey {} -- adminpin {}".format(adminkey,adminPin))
                        if adminkey in admin_pin.keys():
                            print("\n\n in firts if")
                            akey=admin_pin.get(adminkey)
                            if akey == adminPin:
                                print("\n in second if")
                                current_time=datetime.datetime.utcnow().replace(microsecond=0)
                                timeout=current_time+datetime.timedelta(minutes=int(duration))
                                active_hotspot_clients()
                                log.debug("Active clients were {} total clients is {}".format(activeClients,totalClients))
                                if activeClients < totalClients:

                                    record.update({self.client_address[0]: [current_time, timeout, admin_pin]})

                                    self.send_response(200)
                                    self.send_header('Content-type', 'application/json')
                                    self.send_header('Access-control-Allow-Origin', '*')
                                    self.send_header('Acess-Control-Allow-Methods', 'GET, POST, OPTIONS')
                                    self.send_header('Access-Control-Allow-Headers', 'Content-Type, X-Requested-with')
                                    self.end_headers()
                                    self.wfile.write(bytes(json.dumps({"success": "true"}), 'utf-8'))
                                    # windows_firewall()
                                    # log.debug(" Firewall state is -{}".format(windows_firewallstate))
                                    # if windows_firewallstate == "enabled":
                                    #     setTimeout(0, inform_windows_add, self.client_address[0])
                                    try:


                                                dat = {"duration": duration}
                                                log.debug("url {}".format(url))
                                                data = json.dumps(dat).encode("utf-8")
                                                req = urllib.request.Request(url + "/adminHotspotLogin", headers=headers,
                                                                             data=data,
                                                                             method="POST")
                                                resp = urllib.request.urlopen(req, timeout=URL_TIMEOUT)
                                                log.debug("resp code- {}".format(resp.read()))
                                    except Exception as e:
                                                log.debug("Exception raises on calling /adminHotspotLogin = {}".format(e))
                                else:
                                    self.send_response(401)
                                    self.send_header('Content-type', 'application/json')
                                    self.send_header('Access-control-Allow-Origin', '*')
                                    self.send_header('Acess-Control-Allow-Methods', 'GET, POST, OPTIONS')
                                    self.send_header('Access-Control-Allow-Headers',
                                                     'Content-Type, X-Requested-with')
                                    self.end_headers()
                                    self.wfile.write(bytes(json.dumps({"success": "exceed"}), 'utf-8'))
                            else:
                                self.send_response(401)
                                self.send_header('Content-type', 'application/json')
                                self.send_header('Access-control-Allow-Origin', '*')
                                self.send_header('Acess-Control-Allow-Methods', 'GET, POST, OPTIONS')
                                self.send_header('Access-Control-Allow-Headers',
                                                'Content-Type, X-Requested-with')
                                self.end_headers()
                                self.wfile.write(bytes(json.dumps({"success": "false"}), 'utf-8'))
                        else:
                            self.send_response(401)
                            self.send_header('Content-type', 'application/json')
                            self.send_header('Access-control-Allow-Origin', '*')
                            self.send_header('Acess-Control-Allow-Methods', 'GET, POST, OPTIONS')
                            self.send_header('Access-Control-Allow-Headers',
                                             'Content-Type, X-Requested-with')
                            self.end_headers()
                            self.wfile.write(bytes(json.dumps({"success": "false"}), 'utf-8'))
                    
                    else:
                        admin_auth = cs.CSClient().get('zenspace/admin_auth')
                        admin_auth_list = admin_auth.get("data")
                        if admin_auth_list != None:
                            availableadminPins = {};
                            for i in admin_auth_list:
                                availableadminPins.update(i)
                            if adminkey in availableadminPins.keys():
                                apin = availableadminPins.get(adminkey)
                                if adminPin == apin:
                                    current_time=datetime.datetime.utcnow().replace(microsecond=0)
                                    timeout=current_time+datetime.timedelta(minutes=int(duration))
                                    active_hotspot_clients()
                                    log.debug("total clients - {} , active clients - {}".format(totalClients,activeClients))
                                    if activeClients < totalClients:
                                        record.update({self.client_address[0]: [current_time, timeout, apin]})
                                        self.send_response(200)
                                        self.send_header('Content-type', 'application/json')
                                        self.send_header('Access-control-Allow-Origin', '*')
                                        self.send_header('Acess-Control-Allow-Methods', 'GET, POST, OPTIONS')
                                        self.send_header('Access-Control-Allow-Headers', 'Content-Type, X-Requested-with')
                                        self.end_headers()
                                        self.wfile.write(bytes(json.dumps({"success": "true"}), 'utf-8'))
                                        log.debug("calling 9001 port to change the state")
                                        # windows_firewall()
                                        # log.debug(" Firewall state is -{}".format(windows_firewallstate))
                                        # if windows_firewallstate == "enabled":
                                        #     setTimeout(0, inform_windows_add, self.client_address[0])
                                        try:
                                            dat = {"duration": duration}
                                            log.debug("url {}".format(url))
                                            data = json.dumps(dat).encode("utf-8")
                                            req = urllib.request.Request(url + "/adminHotspotLogin", headers=headers,
                                                                         data=data,
                                                                         method="POST")
                                            resp = urllib.request.urlopen(req, timeout=URL_TIMEOUT)
                                            log.debug("resp code- {}".format(resp.read()))
                                        except Exception as e:
                                            log.debug("Exception raises on calling /adminHotspotLogin = {}".format(e))
                                    else:
                                        self.send_response(200)
                                        self.send_header('Content-type', 'application/json')
                                        self.send_header('Access-control-Allow-Origin', '*')
                                        self.send_header('Acess-Control-Allow-Methods', 'GET, POST, OPTIONS')
                                        self.send_header('Access-Control-Allow-Headers', 'Content-Type, X-Requested-with')
                                        self.end_headers()
                                        self.wfile.write(bytes(json.dumps({"success": "exceed"}), 'utf-8'))


                                else:
                                    self.send_response(401)
                                    self.send_header('Content-type', 'application/json')
                                    self.send_header('Access-control-Allow-Origin', '*')
                                    self.send_header('Acess-Control-Allow-Methods', 'GET, POST, OPTIONS')
                                    self.send_header('Access-Control-Allow-Headers',
                                                     'Content-Type, X-Requested-with')
                                    self.end_headers()
                                    self.wfile.write(bytes(json.dumps({"success": "false"}), 'utf-8'))

                            else:
                                self.send_response(401)
                                self.send_header('Content-type', 'application/json')
                                self.send_header('Access-control-Allow-Origin', '*')
                                self.send_header('Acess-Control-Allow-Methods', 'GET, POST, OPTIONS')
                                self.send_header('Access-Control-Allow-Headers', 'Content-Type, X-Requested-with')
                                self.end_headers()
                                self.wfile.write(bytes(json.dumps({"success": "false"}), 'utf-8'))
                        else:
                            self.send_response(500)
                            self.send_header('Content-type', 'application/json')
                            self.send_header('Access-control-Allow-Origin', '*')
                            self.send_header('Acess-Control-Allow-Methods', 'GET, POST, OPTIONS')
                            self.send_header('Access-Control-Allow-Headers', 'Content-Type, X-Requested-with')
                            self.end_headers()
                            self.wfile.write(bytes(json.dumps({"success": "false"}), 'utf-8'))
                else:
                    self.send_response(403)
                    self.send_header('Content-type', 'application/json')
                    self.send_header('Access-control-Allow-Origin', '*')
                    self.send_header('Acess-Control-Allow-Methods', 'GET, POST, OPTIONS')
                    self.send_header('Access-Control-Allow-Headers', 'Content-Type, X-Requested-with')
                    self.end_headers()
                    self.wfile.write(bytes(json.dumps({"success": "false"}), 'utf-8'))
            except Exception as e:
                self.send_response(412)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-control-Allow-Origin', '*')
                self.send_header('Acess-Control-Allow-Methods', 'GET, POST, OPTIONS')
                self.send_header('Access-Control-Allow-Headers', 'Content-Type, X-Requested-with')
                self.end_headers()

                log.debug("exception raised {}".format(e))
                self.wfile.write(bytes(json.dumps({"success": "false"}), 'utf-8'))






    def do_OPTIONS(self):
        self.send_response(200,'OK')
        self.send_header('Content-type', 'text/html')
        self.send_header('Access-control-Allow-Origin', '*')
        self.send_header('Acess-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, X-Requested-with')
        self.end_headers()

##Timer function runs forever.
#It get hotspot client information from the router.Then parse and collect required information for every client that is idle_time,time_entered
#For every client ,the difference of idle_time and time_entered is compared with expiry time of respected record which is in this server
#Revoke the respected client from the router when it reaches its expiry time as well as remove the entry from the record of the server
def call_at_interval(period, callback, args):
    while True:
        sleep(period)
        callback(*args)
def setInterval(period, callback, *args):
    Thread(target=call_at_interval, args=(period, callback, args)).start()
def setTimeout(seconds,callback,*args):
    t = Timer(seconds, callback,args=(args))
    t.start()

def checktime():
    global windows_firewallstate
    print("record is {}".format(record))
    clients = cs.CSClient().get('/status/hotspot')

    json_value = json.dumps(clients, ensure_ascii=True, indent=4)
    json_lines = json_value.split(sep='\n')
    
    try:
     for x, y in record.items():
        
        if (clients.get("data").__getitem__("clients").__contains__(x)):
            # log.debug("in clients")
            

            curtime = datetime.datetime.utcnow().replace(microsecond=0)
            exp_time =y[1]
            print("current time" , curtime , "expired time" , exp_time)
            # log.debug("current time {} ,  expired time {}".format(curtime , exp_time))
            diff=exp_time - curtime
            # log.debug("different of current time and previous time {}".format(diff))

            
            if (curtime > exp_time):
                print("time expired {}".format(x))
                # log.debug("time expired {}".format(x))

                cs.CSClient().put("/control/hotspot/revoke",x)
                record.pop(x)
                # windows_firewall()
                # log.debug(" Firewall state is -{}".format(windows_firewallstate))
                # if windows_firewallstate == "enabled":
                #     setTimeout(0, inform_windows_delete,x)
            else:
                print()
                print("time available for {}".format(x))
                # log.debug("time available for {}".format(x))

        else:
            print()

    except Exception as e:
        print("error occured")
        log.debug("Error occured in checktime {}".format(e))
        print(sys.exc_info())

def revoke_unauthorized_client():
    global record
    print("record is {}".format(record))
    clients = cs.CSClient().get('/status/hotspot')

    json_value = json.dumps(clients, ensure_ascii=True, indent=4)
    json_lines = json_value.split(sep='\n')

    clientList=clients.get("data").__getitem__("clients")
    try:

        if (clientList.__len__() != 0):
            print("processing start")
            for x, y in clientList.items():

                if record.__contains__(x):
                    log.debug("{} connected through verification".format(x))
                else:
                    log.debug(" {} hack".format(x))
                    cs.CSClient().put("/control/hotspot/revoke", x)

    except Exception as e:
        print("error occured")
        log.debug("Error occured in revoke unauthorized client {}".format(e))
        print(sys.exc_info())


setInterval(TIMER, checktime)
setInterval(REVOKE_UNAUTH_TIMER,revoke_unauthorized_client)


if __name__ == '__main__':
    try:
        log.debug("hotspot server")
        try:
            cs.CSClient().put('zenspace/hotspot_clients',totalClients)
            cs.CSClient().put('zenspace/hotspot_method',hotspot_method)
          #  cs.CSClient().put('zenspace/windows_firewall',windows_firewallstate)
            setTimeout(60,code_verify)
        except Exception as e:
            log.debug("Exception raised while setting default totalclient and hostpot method - {}".format(e))
        start_server()

    except Exception as e:
        print('Exception occurred! exception: {}'.format(e))

