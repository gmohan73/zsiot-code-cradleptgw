import cgi
import json
import time
import datetime
import sys
from http.server import HTTPServer, SimpleHTTPRequestHandler
from threading import Thread
from time import sleep
import cs
import settings
from app_logging import AppLogger
import re
log= AppLogger()
global record
record = {}
validverify=''
activeClients=0
TIMER = 10
#Starting server http://{}:9001.This server will run forever
def start_server():
    # avoid 8080, as the router may have service on it.
    # Firewall rules will need to be changed in the router
    # to allow access on this port.
    server_address = ('', 9002)

    print('Starting Server: {}'.format(server_address))
    log.info('Starting Server: {}'.format(server_address))

    log.info('Zenspace hotspot server started');


    httpd = HTTPServer(server_address, WebServerRequestHandler)

    try:
        httpd.serve_forever()

    except KeyboardInterrupt:
        print('Stopping Server, Key Board interrupt')

    return 0

def active_hotspot_clients():
    global activeClients
    clientsList=cs.CSClient().get("/status/hotspot/clients").get("data")
    if clientsList != None:
        activeClients=len(clientsList)
    else:
        activeClients=0

def verifyAuth(pin,client_ip):
    global iot_ip
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
                        totalClients = cs.CSClient().get("zenspace/hotspot_clients").get("data")
                        active_hotspot_clients()
                        log.debug("Actvie clients were {} , total clienets is {}".format(activeClients,
                                                                                                 totalClients))
                        if activeClients < int(totalClients):
                            record.update({client_ip: [timeIn, timeout, pin]})
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



#Server handler
#For Post request-PIN send by the client is validated and return the response as per rule
#IP of client,expiry time is updated to the global record when post request happens
class WebServerRequestHandler(SimpleHTTPRequestHandler):
    print('handler')
    global validverify

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-control-Allow-Origin', '*')
        self.send_header('Acess-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers',
                         'Content-Type, X-Requested-with')
        self.end_headers()
    def do_POST(self):
        log.debug("POST request")
            # expiry_time=0
            # entry_time=time.asctime(time.localtime(time.time()))

        if None != re.search('/doorLock', self.path):

            log.debug("/door post request")
            sensorName = self.path.split('/')[-1]
            log.debug(".....{}".format(sensorName))
            log.debug("headers..{}".format(self.headers))

            # if 'Content-Type' in self.headers:
            #     type = self.headers['Content-Type']
            #     if type == "application/json":

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
            #     else:
            #         self.send_response(415)
            #         self.end_headers()
            #         self.wfile.write(b'BAD Request')
            # else:
            #     self.send_response(412)
            #     self.end_headers()
            #     self.wfile.write(b'BAD Request')

        elif None != re.search('/admindoorLock', self.path):

            log.debug("/admindoorLock post request")

            type = self.headers['Content-Type']
            # if type == "application/json":
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
                                totalClients = cs.CSClient().get("zenspace/hotspot_clients").get("data")
                                log.debug("Active clients were {} total clients is {}".format(activeClients,
                                                                                                      totalClients))
                                if activeClients < int(totalClients):
                                    record.update({self.client_address[0]: [current_time, timeout, apin]})
                                    self.send_response(200)
                                    self.send_header('Content-type', 'application/json')
                                    self.send_header('Access-control-Allow-Origin', '*')
                                    self.send_header('Acess-Control-Allow-Methods', 'GET, POST, OPTIONS')
                                    self.send_header('Access-Control-Allow-Headers', 'Content-Type, X-Requested-with')
                                    self.end_headers()
                                    self.wfile.write(bytes(json.dumps({"success": "true"}), 'utf-8'))
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
                # self.wfile.write(b'BAD Request')
                log.debug("exception raised {}".format(e))
                self.wfile.write(bytes(json.dumps({"success": "false"}), 'utf-8'))
            # else:
            #     self.send_response(415)
            #     self.send_header('Content-type', 'application/json')
            #     self.send_header('Access-control-Allow-Origin', '*')
            #     self.send_header('Acess-Control-Allow-Methods', 'GET, POST, OPTIONS')
            #     self.send_header('Access-Control-Allow-Headers', 'Content-Type, X-Requested-with')
            #     self.end_headers()
            #     self.wfile.write(bytes(json.dumps({"success": "false"}), 'utf-8'))

    #     #cs.CSClient().log()
    #     #fo = open("Record.txt","a")
    #    # print(self.client_address)
    #     form = cgi.FieldStorage(
    #         fp=self.rfile,
    #         headers=self.headers,
    #         environ={'REQUEST_METHOD': 'POST',
    #                  'CONTENT_TYPE': self.headers['Content-Type'],
    #                  })
    #
    #     # Get the information posted in the form
    #     for field in form.keys():
    #         field_item = form[field]
    #
    #
    #
    #
    #
    #
    #     val = field_item.value
    #     print("value is {}".format(val))
    #     pin=val
    #     expiry_time=0
    #     entry_time=time.asctime(time.localtime(time.time()))
    #     self.send_response(200, 'OK')
    #     self.send_header('Content-type', 'application/json')
    #     self.send_header('Access-control-Allow-Origin', '*')
    #     self.send_header('Acess-Control-Allow-Methods', 'GET, POST, OPTIONS')
    #     self.send_header('Access-Control-Allow-Headers', 'Content-Type, X-Requested-with')
    #     self.end_headers()
    #
    #
    #     auth = cs.CSClient().get("zenspace/pin_auth");
    #     # admin_auth=cs.CSClient().get("zenspace/admin_auth")
    #     auth_list = auth.get("data");
    #     # admin_auth_list=admin_auth.get("data")
    #     # print("admin auth list {}".format(admin_auth_list))
    #     # totalpincount = 0
    #     print("auth_list is {}".format(auth_list))
    #     if auth_list != None:
    #         availablePins = {};
    #         totalPins = [];
    #         plist = [];
    #         pinlist = [];
    #         avpins = [];
    #         for p in auth_list:
    #             print("pins were {}".format(p))
    #             availablePins.update(p)
    #         for i, j in availablePins.items():
    #             plist = [];
    #             avpins.append(j.get("pin"))
    #             plist.append(j.get("pin"))
    #             plist.append(i)
    #             plist.append(j.get("TimeOut"))
    #             pinlist.append(plist)
    #
    #         totalpincount = avpins.__len__()
    #         if pin in avpins:
    #             log.debug("pin is there")
    #             validverify = ''
    #             for k in pinlist:
    #                 if pin in k[0]:
    #                     timeIn = datetime.datetime.strptime(k[1], "%Y-%m-%d%H:%M:%S")
    #                     timeOut = datetime.datetime.strptime(k[2], "%Y-%m-%d%H:%M:%S")
    #                     curtime = datetime.datetime.utcnow()
    #                     if (timeIn <= curtime and curtime <= timeOut):
    #                         validverify = "valid"
    #                         log.debug("pin is valid")
    #                         self.wfile.write(bytes(json.dumps({"success": "true"}), 'utf-8'))
    #                         record.update({self.client_address[0]:[timeIn,str(timeOut),val]})
    #
    #                         # return 0
    #
    #
    #                     else:
    #                         log.debug("pin is invalid")
    #                         validverify = "invalid"
    #                         # self.wfile.write(bytes(json.dumps({"success": "timeout"}), 'utf-8'))
    #                         # return 1
    #             if validverify == "invalid":
    #                  self.wfile.write(bytes(json.dumps({"success": "false"}), 'utf-8'))
    #         else:
    #             self.wfile.write(bytes(json.dumps({"success": "false"}), 'utf-8'))
    #     else:
    #         print("auth list is empty")
    #         self.wfile.write(bytes(json.dumps({"success": "false"}), 'utf-8'))
    #     # if validverify == "invalid":
    #     #     self.wfile.write(bytes(json.dumps({"success": "timeout"}), 'utf-8'))
    # # if (pin.__contains__(str(val))):
    #     #
    #     #     expiry_time = pin.get(str(val))
    #     #     curtime = datetime.datetime.utcnow()
    #     #
    #     #
    #     #     if(curtime < expiry_time):
    #     #
    #     #       self.wfile.write(bytes(json.dumps({"success": "true"}), 'utf-8'))
    #     #       record.update({self.client_address[0]:[entry_time,str(expiry_time),val]})
    #     #     else:
    #     #
    #     #         self.wfile.write(bytes(json.dumps({"success": "timeout"}), 'utf-8'))
    #     # else:
    #     #     self.wfile.write(bytes(json.dumps({"success": "false"}), 'utf-8'))
    #     #fo.write('"TIME":"'+ time.asctime( time.localtime(time.time()) )+'","ip": "'+self.client_address[0]+'" , "port" :"'+ self.client_address[1] +'", "pin" : "'+ field_item.value +'","expiry_time(m)": "'+expiry_time +'" \n')
    #
    #     #fo.write('"TIME":"' +entry_time  + '" ,"ip": "' + self.client_address[0] +'" , "port" :'+ str(self.client_address[1])+'"pin" : '+ str(val) + ',"expiry_time(m)": '+str(expiry_time) +' \n' )
    #     #fo.close()
    #
    #



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

def checktime():
    print("record is {}".format(record))
    clients = cs.CSClient().get('/status/hotspot')

    json_value = json.dumps(clients, ensure_ascii=True, indent=4)
    json_lines = json_value.split(sep='\n')
    
    try:
     for x, y in record.items():
        
        if (clients.get("data").__getitem__("clients").__contains__(x)):
            log.debug("in clients")
            
            #time = clients.get("data").__getitem__("clients").get(x).__getitem__("time")
            #idle_time = clients.get("data").__getitem__("clients").get(x).__getitem__("idle_time")

            curtime = datetime.datetime.utcnow().replace(microsecond=0)
            exp_time =y[1]
            print("current time" , curtime , "expired time" , exp_time)
            log.debug("current time {} ,  expired time {}".format(curtime , exp_time))
            diff=exp_time - curtime
            log.debug("different of current time and previous time {}".format(diff))
            # log.debug(curtime>exp_time)
            
            if (curtime > exp_time):
                print("time expired {}".format(x))
                log.debug("time expired {}".format(x))

                cs.CSClient().put("/control/hotspot/revoke",x)
                record.pop(x)
            else:
                print()
                print("time available for {}".format(x))
                log.debug("time available for {}".format(x))

        else:
            print()
            # log.debug("{} record not found".format(x))
    except Exception as e:
        print("error occured")
        log.debug("Error occured in checktime {}".format(e))
        print(sys.exc_info())
        ##log.error("Exception raised...")
        ##log.error(sys.exc_info())


setInterval(TIMER, checktime)



if __name__ == '__main__':
    try:
        totalClients = settings.HOTSPOT_CLIENTS
        cs.CSClient().put("zenspace/hotspot_clients", totalClients)
        start_server()

    except Exception as e:
        print('Exception occurred! exception: {}'.format(e))

