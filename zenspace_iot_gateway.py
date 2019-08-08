import ssl
import json
import time
import datetime
import urllib.request
import urllib.parse
import urllib.response
from base64 import b64encode, b64decode
from hashlib import sha256
from hmac import HMAC
import os
from threading import Thread
from threading import Timer
from threading import active_count
from time import sleep
from http.server import HTTPServer, BaseHTTPRequestHandler
from paho.mqtt import client as mqtt
import cs
import settings
from app_logging import AppLogger
import _thread
import re

#Timers for reporting status to cloud in seconds
GATEWAY_TIMER=300
POD_TIMER=60
SENSOR_TIMER=1800
DEVICE_TIMER=350
CONN_TIMER=12000

#Global variable
log = AppLogger()
devicelist={};
deviceslistbyid={};
devicestatus={};
old_devicelistbyid={};
total_devices='';
zenurl=settings.ZEN_URL
iot_ip=''
podState='Unknown';
prevPodState='';
cloudPodState='';
beforeChangePodState=''
AVAILCOLOR=''
RESERVECOLOR=''
TIMEOUTCOLOR=''
ADMININUSECOLOR=''
RESERVEINUSECOLOR=''
AVAILINBLINK=''
RESERVEINBLINK=''
beforePodState='Unknown'
state="enabled"  #set light state as enabled intitally

#Header for gateway request
headers = {}
headers['content-type'] = 'application/json'

#IOT gateway url
url="http://"
zen_state_url=settings.ZEN_STATE_URL

# Path to the TLS certificates file. The certificates were copied from the certs.c file
# located here: https://github.com/Azure/azure-iot-sdk-c/blob/master/certs/certs.c
path_to_root_cert = os.path.join(os.getcwd(), 'certs.cer')

#Get hubname,podid,podkey from router
hubName__j=cs.CSClient().get('/config/system/asset_id')
podId__j=cs.CSClient().get('/config/system/system_id')
podKey__j=cs.CSClient().get('/config/system/desc')


# MS Azure IoT Hub name
# iot_hub_name='zenhub'
iot_hub_name=hubName__j.get("data")
# Device name in MS Azure IoT Hub
pod_id=podId__j.get("data")
# SAS token for the device id. This can be generated using the Device Explorer Tool.
# The format of the token should be similar to:
# 'SharedAccessSignature sr={your hub name}.azure-devices.net%2Fdevices%2FMyDevice01%2Fapi-version%3D2016-11-14&sig=vSgHBMUG.....Ntg%3d&se=1456481802'
pod_key=podKey__j.get("data")

#SAS token generator.expiry time for generated sas token is a day
def generate_sas_token(uri, key, policy_name, expiry=86400):
    ttl = time.time() + expiry
    sign_key = "%s\n%d" % ((urllib.parse.quote_plus(uri)), int(ttl))
    sign_key = sign_key.encode('utf-8')
    signature = b64encode(HMAC(b64decode(key), sign_key, sha256).digest())

    rawtoken = {
        'sr': uri,
        'sig': signature,
        'se': str(int(ttl))
    }
    return 'SharedAccessSignature ' + urllib.parse.urlencode(rawtoken)

def set_state_color():
    global state,AVAILCOLOR,RESERVECOLOR,TIMEOUTCOLOR,ADMININUSECOLOR,RESERVEINUSECOLOR,AVAILINBLINK,RESERVEINBLINK
    log.debug("setting state color - {} ".format(state))
    if state == "enabled":
        AVAILCOLOR = "green"
        RESERVECOLOR = "orange"
        TIMEOUTCOLOR = "yellow"
        ADMININUSECOLOR = "white"
        RESERVEINUSECOLOR = "white"
        AVAILINBLINK = 3
        RESERVEINBLINK = 3
    else:
        AVAILCOLOR = "white"
        RESERVECOLOR = "white"
        TIMEOUTCOLOR = "white"
        ADMININUSECOLOR = "white"
        RESERVEINUSECOLOR = "white"
        AVAILINBLINK = 0
        RESERVEINBLINK = 0


#Rule engine.Based on podState and state table provided by zenspace,it will change the state of sensors
def update_pod_state():
    global podState,iot_ip,state
    global AVAILCOLOR, RESERVECOLOR, TIMEOUTCOLOR, ADMININUSECOLOR, RESERVEINUSECOLOR, AVAILINBLINK, RESERVEINBLINK
    log.debug("update pod state is -- {},state is - {}".format(podState,state))
    if podState == "Available":
        for k, v in devicelist.items():

            if ("light" in v[2]):
                id = v[0];
                dat = {"on": "true", "color": AVAILCOLOR}
                data = json.dumps(dat).encode('utf-8')
                log.debug("data is {}".format(data))
                log.debug("url {}   and id is {}".format(url+iot_ip, id))
                req = urllib.request.Request(url+iot_ip + '/devices/' + id,
                                             headers=headers, data=data,
                                             method="PUT")
                resp = urllib.request.urlopen(req)
            if ("fan" in k):
                id = v[0];

                dat = {"on": "false"}
                data = json.dumps(dat).encode('utf-8')
                req = urllib.request.Request(url+iot_ip + '/devices/' + id,
                                             headers=headers, data=data,
                                             method="PUT")
                resp = urllib.request.urlopen(req)
    elif podState == "Reserved":
        for k, v in devicelist.items():

            if ("light" in v[2]):
                id = v[0];
                dat = {"on": "true", "color": RESERVECOLOR}
                data = json.dumps(dat).encode('utf-8')
                req = urllib.request.Request(url+iot_ip + '/devices/' + id,
                                             headers=headers, data=data,
                                             method="PUT")
                resp = urllib.request.urlopen(req)
            if ("fan" in k):
                id = v[0];
                dat = {"on": "false"}
                data = json.dumps(dat).encode('utf-8')
                req = urllib.request.Request(url+iot_ip + '/devices/' + id,
                                             headers=headers, data=data,
                                             method="PUT")
                resp = urllib.request.urlopen(req)
    elif podState == "Admin In Use":
        for k, v in devicelist.items():

            if ("light" in v[2]):
                id = v[0];
                dat = {"on": "true", "color": ADMININUSECOLOR}
                data = json.dumps(dat).encode('utf-8')
                req = urllib.request.Request(url+iot_ip + '/devices/' + id,
                                             headers=headers, data=data,
                                             method="PUT")
                resp = urllib.request.urlopen(req)

            if ("fan" in k):
                id = v[0];
                dat = {"on": "true"}
                data = json.dumps(dat).encode('utf-8')
                req = urllib.request.Request(url+iot_ip + '/devices/' + id,
                                             headers=headers, data=data,
                                             method="PUT")
                resp = urllib.request.urlopen(req)
    elif podState == "Reservation In Use":

        for k, v in devicelist.items():

            if ("light" in v[2]):
                id = v[0];

                dat = {"on": "true", "color": RESERVEINUSECOLOR}
                data = json.dumps(dat).encode('utf-8')
                req = urllib.request.Request(url+iot_ip + '/devices/' + id,
                                             headers=headers, data=data,
                                             method="PUT")
                resp = urllib.request.urlopen(req)

            if ("fan" in k):
                id = v[0];
                dat = {"on": "true"}
                data = json.dumps(dat).encode('utf-8')
                req = urllib.request.Request(url+iot_ip + '/devices/' + id,
                                             headers=headers, data=data,
                                             method="PUT")
                resp = urllib.request.urlopen(req)
    elif podState == "TimeOut":
        for k, v in devicelist.items():

            if ("light" in v[2]):
                id = v[0];
                dat = {"on": "true", "color": TIMEOUTCOLOR}

                data = json.dumps(dat).encode('utf-8')
                req = urllib.request.Request(url+iot_ip + '/devices/' + id,
                                             headers=headers, data=data,
                                             method="PUT")
                resp = urllib.request.urlopen(req)
            if ("fan" in k):
                id = v[0];
                dat = {"on": "true"}
                data = json.dumps(dat).encode('utf-8')
                req = urllib.request.Request(url+iot_ip + '/devices/' + id,
                                             headers=headers, data=data,
                                             method="PUT")
                resp = urllib.request.urlopen(req)
    elif podState == "Available in Next 10 min":
        for k, v in devicelist.items():

            if ("light" in v[2]):
                id = v[0];

                dat = {"command":"identify","duration":AVAILINBLINK}
                data = json.dumps(dat).encode('utf-8')
                req = urllib.request.Request(url+iot_ip + '/devices/' + id,
                                             headers=headers, data=data,
                                             method="PUT")
                resp = urllib.request.urlopen(req)
            if ("fan" in k):
                id = v[0];
                dat = {"on": "true"}
                data = json.dumps(dat).encode('utf-8')
                req = urllib.request.Request(url+iot_ip + '/devices/' + id,
                                             headers=headers, data=data,
                                             method="PUT")
                resp = urllib.request.urlopen(req)
    elif podState == "Unknown":
        for k, v in devicelist.items():

            if ("light" in v[2]):
                id = v[0];

                dat = {"on": "true", "color":"white"}
                data = json.dumps(dat).encode('utf-8')
                req = urllib.request.Request(url+iot_ip + '/devices/' + id,
                                             headers=headers, data=data,
                                             method="PUT")
                resp = urllib.request.urlopen(req)

            if ("fan" in k):
                id = v[0];
                dat = {"on": "true"}
                data = json.dumps(dat).encode('utf-8')
                req = urllib.request.Request(url+iot_ip + '/devices/' + id,
                                             headers=headers, data=data,
                                             method="PUT")
                resp = urllib.request.urlopen(req)
    elif podState == "Reserved in Next 10 min":
        for k, v in devicelist.items():

            if ("light" in v[2]):
                id = v[0];
                dat = {"command": "identify", "duration": RESERVEINBLINK}
                data = json.dumps(dat).encode('utf-8')
                req = urllib.request.Request(url+iot_ip + '/devices/' + id,
                                             headers=headers, data=data,
                                             method="PUT")
                resp = urllib.request.urlopen(req)
            if ("fan" in k):
                id = v[0];
                dat = {"on": "true"}
                data = json.dumps(dat).encode('utf-8')
                req = urllib.request.Request(url+iot_ip + '/devices/' + id,
                                             headers=headers, data=data,
                                             method="PUT")
                resp = urllib.request.urlopen(req)

    sensor_status(0)

#Update pod state to salesforce
def inform_pod_state():
    global podState
    dat = {"state":podState}
    headers={"Content-Type":"application/x-www-form-urlencoded"}
    try:
        data = urllib.parse.urlencode(dat).encode('utf-8')
        req = urllib.request.Request(zen_state_url + pod_id + "/", headers=headers, data=data, method="POST")
        resp = urllib.request.urlopen(req)
        log.debug("url {}".format(zen_state_url + pod_id + "/"))
        log.debug("sending state is -- {} ".format(podState))
        log.debug("response from zenStateURL {}".format(json.loads(resp.read())))


    except Exception as e:
        log.debug("Exception raised in inform_pod_state-- {}".format(e))

        mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + grid,
                            "{\"pod_state\":\"" + podState + "\"}",
                            qos=0)

#Change pod state after admin tmieout.When state is "Admin In Use",state pushed by cloud is hold.After "Admin Timeout" ,the cloud pushed state is replaced.If cloud doesnot push any state ,in between "Admin In Use" and "Admin TmeOut",the previous state maintained by cradlepoint will be replaced.
def change_prev_pod_state():
    global podState,prevPodState,cloudPodState
    log.debug("changing pod state after admin timeout -- ")
    log.debug("cloud pushed state - {} , prevPod state -- {}".format(cloudPodState,prevPodState))
    if cloudPodState == '' or cloudPodState == None:
        podState=prevPodState
    else:
        podState=cloudPodState
        cloudPodState=''
    mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + grid,
                        "{\"pod_state\":\"" + podState + "\"}",
                        qos=0)
    update_pod_state()
    sensor_status(0)
    inform_pod_state()

#To change pod state,update pod state to cloud and sales force
def change_pod_state(state):

    global podState
    if( podState == "Admin In Use"):
        log.debug("Reservation Timeout is bypassed,because pod used by Admin")
    else:
        podState=state
        mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + grid,
                            "{\"pod_state\":\"" + podState + "\"}",
                            qos=0)
        update_pod_state()
        sensor_status(0)
        inform_pod_state()



# Called when the broker responds to our connection request.
def on_connect(client, userdata, flags, rc):
    log.info('Device connected with result code: {}'.format(rc))


    # Subscribing in on_connect() means that if we lose the connection and
    # reconnect then subscriptions will be renewed.
    #Twin properties and events releated topics subscribed to get the message from cloud
    try:
        client.subscribe('devices/{}/messages/devicebound/#'.format(pod_id))     #cloud send messages under this topic by default
        client.subscribe('devices/{}/messages/events/#'.format(pod_id))
        client.subscribe("$iothub/twin/res/#")                                      #cloud send response for twin response under this topic by default
        client.subscribe('$iothub/twin/PATCH/properties/#')
        # client.subscribe('$iothub/twin/GET/#')




    except Exception as ex:
        log.error('Client Subscribe exception. ex={}'.format(ex))



# Called when the broker responds to our disconnect request.
def on_disconnect(client, userdata, rc):
    log.info('Device disconnected with result code: {}'.format(rc))
    if rc == 5:
        mqtt_client.username_pw_set(username=iot_hub_name + '.azure-devices.net/' + pod_id + '/api-version=2018-06-30',
                                    password=generate_sas_token(iot_hub_name + ".azure-device.net/devices" + pod_id,
                                                                pod_key, pod_id))



# Called when a message that was to be sent using the publish() call has
# completed transmission to the broker.
#
# This callback is important because even if the publish() call returns success,
# it does not always mean that the message has been sent.
def on_publish(client, userdata, mid):

    # log.info('Device sent message')

    pass


# Called when the broker responds to a subscribe request. The mid variable
# matches the mid variable returned from the corresponding subscribe() call.
# The granted_qos variable is a list of integers that give the QoS level the
# broker has granted for each of the different subscription requests.
def on_subscribe(client, userdata, mid, granted_qos):
    log.debug('Subscribe response: Message ID={}, granted_qos={}'.format(mid, granted_qos))

# Called when a message has been received on a topic that the client subscribes
# to and the message does not match an existing topic filter callback. Use
# message_callback_add() to define a callback that will be called for specific
# topic filters. on_message will serve as fallback when none matched.

#Desired properties sent by the cloud is converted into json format.Key is the device name and value is operation need to perform.
#Get identity for the device from deviceslist dictionary.Then request is passed to the IOT gateway
def on_message(client, userdata, msg):
    global iot_ip,cloudPodState,state
    log.debug('Device received topic: {}, msg: {}'.format(msg.topic, str(msg.payload.decode("utf-8"))))
    topic=msg.topic;

    req_body={};
    publish_response={};
    if "/properties/desired" in topic:
     try:
        res=json.loads(msg.payload)
        for x,y in res.items():
            if x == '$version':
                break
            if x == 'pin_auth':
                re=cs.CSClient().delete('zenspace/pin_auth')

                try:
                    au=json.dumps(y)
                    count=0
                    for k,v in y.items():
                        # data={k:{"TimeIn":v.get("TimeIn"),"TimeOut":v.get("TimeOut")}}
                        data = { k: {"pin":v.get("pin"), "TimeOut": v.get("TimeOut")}}
                        s = cs.CSClient().put('zenspace/pin_auth/'+str(count),data)
                        log.debug("reservation pin response {}".format(s))
                        count=count+1

                    # s=cs.CSClient().post('zenspace/auth',au)

                except Exception as e:
                    log.debug("exception in saving the pin {}".format(e))
            elif x == "admin_auth":
                re = cs.CSClient().delete('zenspace/admin_auth')

                try:
                    au = json.dumps(y)
                    log.debug("admin _auth pin -{} = {} ".format(x,y))
                    count=0
                    for k, v in y.items():
                        data = {k: v}
                        log.debug("key is {},value is {}".format(k,v))
                        # s = cs.CSClient().post('zenspace/admin_auth/', data)
                        s = cs.CSClient().put('zenspace/admin_auth/'+str(count), data)
                        log.debug("admin pin response {}".format(s))
                        count=count+1

                    # s=cs.CSClient().post('zenspace/auth',au)

                except Exception as e:
                    log.debug("exception in saving the pin {}".format(e))
            elif x == "pod_state":
                global podState,beforePodState
                beforePodState=podState
                log.debug("pod state updated by {}".format(podState))
                cloudPodState=y
                if podState == "Admin In Use":
                    log.debug(" Admin In use,cloud pushed state is by passed")
                    pass
                else:
                    podState = y
                    if podState == "Reserved in Next 10 min" or podState == "Available in Next 10 min":
                        log.debug("pod state R10 or A10")
                        if beforePodState == "Reservation In Use":
                            log.debug("prev pod state is RIU,updating state")
                            update_pod_state()
                        else:
                            log.debug("pod state is R10 or A10 but pod not in use")
                            pass
                    else:
                        update_pod_state()
                mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + grid,
                                    "{\"pod_state\":\"" + podState + "\"}",
                                    qos=0)
            elif x == "light_state":
                log.debug("state of the light updated - {}".format(y))
                state=y
                set_state_color()
                update_pod_state()
            elif devicelist.__contains__(x):

                id=devicelist.__getitem__(x)[0]

                data = json.dumps(y).encode('utf-8')
                log.debug("data is {}".format(data))
                req=urllib.request.Request(url+iot_ip+'/devices/'+id,headers=headers,data=data,method="PUT")
                resp = urllib.request.urlopen(req)
                log.debug("response from gateway -- {}".format(resp))
                # single_sensor_status(id)
                start=0
                sensor_status(start)
            else:
                log.debug("no such device - {}".format(x))


     except Exception as e:
         log.error("Exception occurs in message processing -{}".format(e))

#Note:sensor status and device list functions are recurssion function because at a given time IOT gateway responds as it can.

#Getting the gateway status from IOT gateway api and twin property reported to cloud

def gateway_status():
    global iot_ip
    res='';
    try:
        res=urllib.request.urlopen(url+iot_ip+'/gateway')
        gres=res.read()
        gateway_response= json.loads(gres)
        status=gateway_response.get("gateway").get("info").get("state")

    except Exception as ex:
        log.debug('gateway not reachable-{}'.format(ex))
        status="Not connected"


    mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + grid,
                    "{\"gateway_status\":\"" + status + "\"}", qos=0)
    log.info('Gateway status published')




#Current local time of the cradle point is treated as pod keep-alive time.
def pod_status():
    # currenttime = time.asctime(time.localtime(time.time()))

    log.debug("  Number of active threads == {}".format(active_count()))
    currenttime=str(datetime.datetime.utcnow().replace(microsecond=0))
    mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + grid,
                        "{\"pod_rxtime\":\"" + currenttime + "\"}", qos=0)

    log.info('POD Status published')
#Getting single sensor status
def single_sensor_status(sensor_id):
    global iot_ip
    srid="2000"
    response = urllib.request.urlopen(url+iot_ip + '/devices/status/'+sensor_id)
    respData = response.read();
    res = json.loads(respData)
    list = res.get("deviceStatus").get("list")
    for x in list:

        identifier = x.get("identifier")
        color = '';
        if x.get("colorHue") != None:

            hue = x.get("colorHue")
            sat = x.get("colorSat")
            if hue == "150":
                color = 'blue'
            elif hue == "80":
                color = 'green'
            elif hue == "30":
                color = 'yellow'
            elif hue == "10":
                color = 'orange'
            elif hue == "210":
                color = 'purple'
            elif hue == "0" and sat == "250":
                color = 'red'
            else:
                color = 'white'
        if deviceslistbyid.__contains__(identifier):
            rep_prop = {};
            rep_status = {};
            name = deviceslistbyid.__getitem__(identifier)[0];
            deviceType = deviceslistbyid.__getitem__(identifier)[1];
            mfg=deviceslistbyid.__getitem__(identifier)[2];
            model=deviceslistbyid.__getitem__(identifier)[3]
            rep_status.update({"deviceType": deviceType})
            rep_status.update({"mfg":mfg})
            rep_status.update({"model":model})

            for y, z in x.items():
                if y == "rxTime":
                    rep_status.update({y: str(datetime.datetime.utcfromtimestamp(z))})
                elif y == "colorHue":
                    rep_status.update(({"color": color}))
                elif y == "colorSat" or y == "colorTemp":
                    pass
                else:
                    rep_status.update({y: z})

            rep_prop.update({name: rep_status})
            if name == "" or str(name).__contains__(" "):
                pass
            else:
                mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + srid,
                                    str(rep_prop), qos=0)

    log.info('sensor status published')

#Status for sensors which all are connected to IOT gateway was read.
#IOT gateway status api returns identity not name.Name is taken from devicelistbyid dictionary.
#If the sensor has color properties,color is determined by colorHue and colorSat of that
#Reported property for sensors is created like the following format { ":device name" : { ":property key" : ":value" } }
def sensor_status(startIndex):
   global total_devices,iot_ip
   if (startIndex >= total_devices):
       return 1
   srid='4'

   try:
       response=urllib.request.urlopen(url+iot_ip + '/devices/status?startIndex='+str(startIndex))
       respData=response.read();
       res=json.loads(respData)
       list = res.get("deviceStatus").get("list")
       count=0
       for x in list:
           count=count+1
           identifier = x.get("identifier")
           color = '';
           if x.get("colorHue") != None:

               hue = x.get("colorHue")
               sat = x.get("colorSat")
               if hue == "150":
                   color = 'blue'
               elif hue == "80":
                   color = 'green'
               elif hue == "30":
                   color = 'yellow'
               elif hue == "10":
                   color = 'orange'
               elif hue == "210":
                   color = 'purple'
               elif hue == "0" and sat == "250":
                   color = 'red'
               else:
                   color = 'white'

           if deviceslistbyid.__contains__(identifier):
               rep_prop = {};
               rep_status = {};
               name = deviceslistbyid.__getitem__(identifier)[0];
               deviceType = deviceslistbyid.__getitem__(identifier)[1];
               mfg=deviceslistbyid.__getitem__(identifier)[2];
               model = deviceslistbyid.__getitem__(identifier)[2];

               rep_status.update({"deviceType": deviceType})
               rep_status.update({"mfg":mfg});
               rep_status.update({"model":model})

               for y, z in x.items():
                   if y == "rxTime":
                       rep_status.update({y: str(datetime.datetime.utcfromtimestamp(z))})
                   elif y == "colorHue":
                       rep_status.update(({"color": color}))
                   elif y == "colorSat" or y == "colorTemp":
                       pass
                   else:
                       rep_status.update({y: z})


               rep_prop.update({name: rep_status})

               if name == "" or str(name).__contains__(" "):
                 pass
               else:
                 devicestatus.update(rep_prop)
                 mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + srid,
                    str(rep_prop), qos=0)
                 mqtt_client.publish('devices/' + pod_id + '/messages/events/',json.dumps(rep_prop),qos=1)

       # log.info('sensor status published')
       return sensor_status(startIndex+count)
   except Exception as e:
        log.debug("Processing sensor status fails {}".format(e))
        return 1


#Number of bytes transfered and received through the cradle point's lan and wan network is send to cloud as telementery data

def network_stats():
    conn_type=cs.CSClient().get("/status/wan/primary_device").get("data")
    mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + grid,
                        "{\"conn_type\":\"" + conn_type + "\"}", qos=0)

    wan_in=cs.CSClient().get("/status/stats/usage/wan_in").get("data");
    wan_out=cs.CSClient().get("/status/stats/usage/wan_out").get("data");
    lan_in=cs.CSClient().get("/status/stats/usage/lan_in").get("data");
    lan_out=cs.CSClient().get("/status/stats/usage/lan_out").get("data");
    for (wi,wo,li,lo) in zip(wan_in,wan_out,lan_in,lan_out):
      mqtt_client.publish('devices/' + pod_id + '/messages/events/', "{\"wan_in\":" + str(wi) + " , \"wan_out\" :"+str(wo)+" ,\"lan_in\" :"+str(li)+ ", \"lan_out\" : "+str(lo)+ " }",
                        qos=1)


#Total devices connected to IOT gateway
def get_number_of_devices():
    global total_devices
    global iot_ip
    try:
        log.debug("get number of devices -- url is {}".format("http://"+iot_ip))
        res=urllib.request.urlopen(url+iot_ip + '/devices')
        nres=res.read()
        number_of_devices= json.loads(nres)
        total_devices=number_of_devices.get("devices").get("totalDevices")
        return total_devices;
    except Exception as e:

        log.debug("retreiving number of devices fails {}".format(e))
        return 0


#Devices name,type and identifier which all are connected to IOT gateway is stored in dictionary for further references
def device_list(startIndex):
    global total_devices,iot_ip
    total_devices = get_number_of_devices()

    if (startIndex >= total_devices):
        return 1

    try:
            response=urllib.request.urlopen(url+iot_ip + '/devices/info?startIndex='+str(startIndex))
            dres=response.read()
            res=json.loads(dres);
            list = res.get("deviceInfo").get("list")
            count=0;
            for x in list:
                identifier=x.get("identifier")
                name=x.get("name")
                deviceType=x.get("deviceType")
                mfg=x.get("mfg")
                model=x.get("model")
                if "hasColorHue" in x.keys() or "hasColorSat" in x.keys() or "hasColorTemp" in x.keys():
                    lightPurpose="light"
                else:
                    lightPurpose="other"

                devicelist.update({name:[identifier,deviceType,lightPurpose]})
                deviceslistbyid.update({identifier:[name,deviceType,mfg,model]})
                count=count+1;
            return device_list(startIndex+count)

    except Exception as e:
            log.debug("Retrieving device list fails -{}".format(e))
            return 1




#If device name is renamed on IOTgateway,the old name reported properties is deleted from the cloud

def device_list_manage():

    for i in old_devicelistbyid.keys():
        if (i in deviceslistbyid.keys()):
            if old_devicelistbyid.get(i)[0] != deviceslistbyid.get(i)[0]:
                mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + grid,
                                      "{\""+old_devicelistbyid.get(i)[0]+"\":null}", qos=0)


    old_devicelistbyid.update(deviceslistbyid.copy())

#IPadServer
def start_server():
    server_address = ('', 9001)

    print('Starting Server: {}'.format(server_address))
    log.info('IPadServer started');

    httpd = HTTPServer(server_address, SimpleHTTPRequestHandler)
    # httpd.socket = ssl.wrap_socket(httpd.socket, certfile='./server.pem',server_side=True)

    try:
        httpd.serve_forever()


    except KeyboardInterrupt:
        print('Stopping Server, Key Board interrupt')

    return 0

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    global podState,iot_ip,state,beforePodState
    def do_GET(self):

        if None != re.search('/sensor/status',self.path):
            try:


                sensor_status(0)
                self.send_response(200)
                self.send_header('Content-Type','application/json')
                self.end_headers()
                s=json.dumps(devicestatus).encode('utf-8')

                self.wfile.write(s)
            except Exception as e:
                log.debug("Exception occurs in get /sensor/info --{}".format(e))
                self.send_response(503)
                self.end_headers()
        elif None != re.search('/pod/state',self.path):

            log.debug("pod state is {}".format(podState))
            podstate={"state":podState}
            self.send_response(200)
            self.send_header('Content-Type','application/json')
            self.end_headers()
            podstateData=json.dumps(podstate).encode('utf-8')
            self.wfile.write(podstateData)

        elif None != re.search('/podLightstate', self.path):

            log.debug("pod state is {}   light state is {}".format(podState,state))
            podstate = {"podState": podState , "lightState":state ,"prevpodState":beforePodState}
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            podstateData = json.dumps(podstate).encode('utf-8')
            self.wfile.write(podstateData)

        else:
            self.send_response(404)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'Invalid URL')








    def do_POST(self):
        log.debug("POST request")
        global podState, prevPodState
        if None != re.search('/doorLock', self.path):


                log.debug("/door post request")

                log.debug("headers..{}".format(self.headers))
                global podState
                log.debug("/doorLock state of the pod is  {}".format(podState))
                # if podState == "Admin In Use":
                #     self.send_response(503)
                #     self.end_headers()
                #     self.wfile.write(b'Admin In Use')
                # else:

                if 'Content-Type' in self.headers:
                    type = self.headers['Content-Type']
                    if type == "application/json":
                        try:
                            content_length = int(self.headers['Content-Length'])


                            log.debug("content length is {}".format(content_length))
                            body = self.rfile.read(content_length)
                            log.debug("request body - {}".format(body))

                            data = json.loads(body)
                            conn_state = cs.CSClient().get("/status/wan/connection_state").get("data")
                            if conn_state.lower() == "connected":
                                for x, y in data.items():

                                    if x == "pin":
                                       s = verifyAuth(y)

                                       if s == 0:
                                           log.debug("Reservation user logging in ,state is--{}".format(podState))


                                           log.debug("Admin is not there")
                                           self.send_response(200)
                                           self.end_headers()
                                           self.wfile.write(b'Door Opened')
                                           log.debug("response code is {} - response text is {}".format("200","Door Opened"))

                                           update_pod_state()

                                           sensor_status(0)
                                           inform_pod_state()

                                       elif s == 1:
                                           self.send_response(401)
                                           self.end_headers()
                                           self.wfile.write(b'UnAuthorized')
                                       elif s == 2:
                                           self.send_response(500)
                                           self.end_headers()
                                           self.wfile.write(b'Fail to reach gateway')
                                       elif s == 20:
                                           self.send_response(412)
                                           self.end_headers()
                                           self.wfile.write(b'No door sensor')
                                       elif s == 202:
                                           self.send_response(202)
                                           self.end_headers()
                                           self.wfile.write(b'Accepted')
                                           log.debug("response code is {} - response text is {}".format("202", "Accepted"))
                                       elif s == 212:
                                           self.send_response(503)
                                           self.end_headers()
                                           self.wfile.write(b'Admin In Use')
                                       else:
                                           self.send_response(500)
                                           self.end_headers()
                                           self.wfile.write(b'Unexpected error')


                                    else:
                                        self.send_response(403)
                                        self.end_headers()
                                        self.wfile.write(b'BAD Request')
                            else:
                                self.send_response(503)
                                self.end_headers()
                                self.wfile.write(b'Service Unavailable')
                        except Exception as e:
                            log.debug("Exception raised in /doorLock post request {}".format(e))
                            self.send_response(412)
                            self.end_headers()
                            self.wfile.write(b'BAD Request')
                    else:
                        self.send_response(415)
                        self.end_headers()
                        self.wfile.write(b'BAD Request')
                else:
                        self.send_response(412)
                        self.end_headers()
                        self.wfile.write(b'BAD Request')

        elif None != re.search('/admindoorLock', self.path):

                log.debug("/admindoorLock post request")


                type = self.headers['Content-Type']
                if type == "application/json":
                    try:
                        content_length = int(self.headers['Content-Length'])

                        log.debug("content length is {}".format(content_length))
                        body = self.rfile.read(content_length)
                        log.debug("request body - {}".format(body))

                        data = json.loads(body)
                        if "adminpin" in data.keys() and "adminkey" in data.keys() and "duration" in data.keys():
                            adminPin = data.get("adminpin")
                            adminkey=data.get("adminkey")
                            duration=data.get("duration")
                            admin_auth=cs.CSClient().get('zenspace/admin_auth')
                            admin_auth_list=admin_auth.get("data")
                            if admin_auth_list != None:
                                availableadminPins = {};
                                for i in admin_auth_list:

                                    availableadminPins.update(i)
                                if adminkey in availableadminPins.keys():
                                    apin=availableadminPins.get(adminkey)
                                    if adminPin == apin :


                                        if devicelist.__contains__("door_lock"):
                                            id = devicelist.__getitem__("door_lock")[0]

                                            # log.debug("door id is {}".format(d))
                                            dat = {"on": "true"}

                                            # log.debug("data is {}".format(data))
                                            data = json.dumps(dat).encode('utf-8')
                                            req = urllib.request.Request(url+iot_ip + '/devices/' + id, headers=headers, data=data,
                                                                         method="PUT")
                                            resp = urllib.request.urlopen(req)

                                            if (resp.status == 200):
                                                self.send_response(200)
                                                self.end_headers()
                                                self.wfile.write(b'Door Opened')
                                                # global podState,prevPodState
                                                prevPodState = podState
                                                podState = "Admin In Use"

                                                update_pod_state()
                                                mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + grid,
                                                                    "{\"pod_state\":\"" + podState + "\"}",
                                                                    qos=0)

                                                sensor_status(0)
                                                inform_pod_state()
                                                setTimeoutMinutes(int(duration),change_prev_pod_state)
                                            else:
                                                self.send_response(500)
                                                self.end_headers()
                                                self.wfile.write(b'Fail to reach gateway')

                                        else:

                                            log.debug("door lock device id missing")
                                            self.send_response(412)
                                            self.end_headers()
                                            self.wfile.write(b'No door sensor')
                                    else:
                                        self.send_response(401)
                                        self.end_headers()
                                        self.wfile.write(b'UnAuthorized')
                                else:
                                    self.send_response(401)
                                    self.end_headers()
                                    self.wfile.write(b'UnAuthorized')
                            else:
                                self.send_response(500)
                                self.end_headers()
                                self.wfile.write(b'Admin pin is missing')
                        else:
                            self.send_response(403)
                            self.end_headers()
                            self.wfile.write(b'BAD Request')
                    except Exception as e:
                        self.send_response(412)
                        self.end_headers()
                        self.wfile.write(b'BAD Request')
                else:
                    self.send_response(415)
                    self.end_headers()
                    self.wfile.write(b'BAD Request')

        elif None != re.search('/pod/state',self.path):
            type = self.headers['Content-Type']
            if type == "application/json":
                content_length = int(self.headers['Content-Length'])
                body = self.rfile.read(content_length)
                log.debug("body is {}".format(body))
                log.debug("request body - {}".format(body))

                data = json.loads(body)
                if "state" in data.keys():
                    state=data.get("state")

                    podState=state
                    if podState == state:
                        self.send_response(200)
                        self.end_headers()
                        dat={"status":"Pod state is updated"}
                        data=json.dumps(dat).encode("utf-8")
                        self.wfile.write(data)
                        update_pod_state()
                        mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + grid,
                                            "{\"pod_state\":\"" + podState + "\"}",
                                            qos=0)
                    else:
                        self.send_response(304)
                        self.end_headers()
                        dat = {"status": "Pod state is not updated"}
                        data = json.dumps(dat).encode("utf-8")
                        self.wfile.write(data)
                else:
                    self.send_response(403)
                    self.end_headers()
                    dat = {"status": "BAD request"}
                    data = json.dumps(dat).encode("utf-8")
                    self.wfile.write(data)

            else:
                self.send_response(415)
                self.end_headers()
                dat = {"status": "BAD request"}
                data = json.dumps(dat).encode("utf-8")
                self.wfile.write(data)

        elif None != re.search('/Lightsensor',self.path):
            log.debug("headers for /Lightsensor rrequest {}".format(self.headers))
            type = self.headers['Content-Type']
            if 'Content-Type' in self.headers:
                if type == "application/json":
                    try:
                        content_length = int(self.headers['Content-Length'])
                        body = self.rfile.read(content_length)
                        log.debug("body is {}".format(body))
                        try:
                            device_list(0)
                            for k, v in devicelist.items():

                                if ("light" in v[2]):
                                    id = v[0];
                                    data = json.loads(body)
                                    log.debug("data is {}".format(data))
                                    log.debug("url {}   and id is {}".format(url + iot_ip, id))
                                    req = urllib.request.Request(url+iot_ip + '/devices/' + id, headers=headers, data=json.dumps(data).encode('utf-8'), method="PUT")
                                    resp = urllib.request.urlopen(req)


                            self.send_response(200);
                            self.end_headers()
                            self.wfile.write(b'Success')
                            sensor_status(0)


                        except Exception as e:
                            log.debug("Exception occurs in PUT /sensor/ --{}".format(e))
                            self.send_response(500);
                            self.end_headers()
                            self.wfile.write(b'Fail to reach gateway')
                    except Exception as e:
                        log.debug("exception raised in /sensor request {}".format(e))
                        self.send_response(412)
                        self.end_headers()
                        self.wfile.write(b'BAD Request'+e)
                else:
                    self.send_response(415)
                    self.end_headers()
                    self.wfile.write(b'BAD Request')
            else:
                self.send_response(412)
                self.end_headers()
                self.wfile.write(b'BAD Request')
        elif None != re.search('/sensor/*', self.path):
            sensorName=self.path.split('/')[-1]
            log.debug("headers for /sensor rrequest {}".format(self.headers))
            log.debug("sensor name is {}".format(sensorName))
            type = self.headers['Content-Type']
            if 'Content-Type' in self.headers:
                if type == "application/json":
                    try:
                        content_length = int(self.headers['Content-Length'])
                        body = self.rfile.read(content_length)
                        log.debug("body is {}".format(body))
                        try:
                            if devicelist.__contains__(sensorName):
                                log.debug("device id present")
                                id = devicelist.__getitem__(sensorName)[0]
                                data = json.loads(body)
                                log.debug("data is {}".format(data))
                                req = urllib.request.Request(url+iot_ip + '/devices/' + id, headers=headers, data=json.dumps(data).encode('utf-8'), method="PUT")
                                resp = urllib.request.urlopen(req)
                                log.debug(resp.status)
                                if resp.status == 200:
                                    self.send_response(200);
                                    self.end_headers()
                                    self.wfile.write(b'Success')
                                    sensor_status(0)
                                else:
                                    self.send_response(500);
                                    self.end_headers()
                                    self.wfile.write(b'Failure')
                            else:
                                self.send_response(412)
                                self.end_headers()
                                self.wfile.write(b'Invalid sensor')
                        except Exception as e:
                            log.debug("Exception occurs in PUT /sensor/ --{}".format(e))
                            self.send_response(500);
                            self.end_headers()
                            self.wfile.write(b'Fail to reach gateway')
                    except Exception as e:
                        log.debug("exception raised in /sensor request {}".format(e))
                        self.send_response(412)
                        self.end_headers()
                        self.wfile.write(b'BAD Request')
                else:
                    self.send_response(415)
                    self.end_headers()
                    self.wfile.write(b'BAD Request')
            else:
                self.send_response(412)
                self.end_headers()
                self.wfile.write(b'BAD Request')

        else:
            log.debug("Invalid url");
            self.send_response(404);
            self.end_headers()

        # self.wfile.write(response.getvalue())




def verifyAuth(pin):
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
                        if devicelist.__contains__("door_lock"):
                            id = devicelist.__getitem__("door_lock")[0]

                            # log.debug("door id is {}".format(d))
                            response = urllib.request.urlopen(url + iot_ip + '/devices/status/' + id)
                            dres = response.read()
                            res = json.loads(dres);
                            dstatus = res.get("deviceStatus")

                            list = res.get("deviceStatus").get("list")
                            currenttime = datetime.datetime.utcnow().replace(microsecond=0)
                            for l in list:
                                lctimestamp = l.get("rxTime")
                                lctime = datetime.datetime.utcfromtimestamp(lctimestamp)
                                diff = currenttime - lctime
                                diffsec=diff.seconds
                                if (diffsec < 900):
                                    dat = {"on": "true"}
                                    # log.debug("data is {}".format(data))
                                    data = json.dumps(dat).encode('utf-8')
                                    req = urllib.request.Request(url + iot_ip + '/devices/' + id, headers=headers,
                                                                 data=data,
                                                                 method="PUT")
                                    resp = urllib.request.urlopen(req)
                                    if (resp.status == 200):
                                        global podState
                                        if podState == "Admin In Use":
                                            return 212
                                        podState = "Reservation In Use"
                                        mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + grid,
                                                            "{\"pod_state\":\"" + podState + "\"}",
                                                            qos=0)
                                        currentPin = pin

                                        diff = timeOut - curtime

                                        timeOutSeconds = diff.seconds - 60
                                        setTimeout(timeOutSeconds, change_pod_state, "TimeOut")

                                        return 0
                                else:
                                    return 20



                            else:
                                return 2
                            # log.debug("gaeway response {}".format(resp))
                        else:

                            log.debug("door lock device id missing")
                            return 20
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
                        return getAuthentications(pin,totalpincount)
                else:
                    return getAuthentications(pin,totalpincount)



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
                  return getAuthentications(pin, totalpincount)
            else:
                 return getAuthentications(pin, totalpincount)


def getAuthentications(pin,count):
    try:

        dat = {"start_datetime": datetime.datetime.strftime(datetime.datetime.utcnow(), "%Y-%m-%d %H:%M:%S"),
               "end_datetime": datetime.datetime.strftime(datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
                                                          "%Y-%m-%d %H:%M:%S")}

        data=urllib.parse.urlencode(dat)
        req = urllib.request.Request(zenurl + pod_id + "/?" + data, headers=headers, method="GET")
        resp = urllib.request.urlopen(req)
        zres=json.loads(resp.read())

        zreskv = zres.get("result")

        totalPins_gA = [];
        auth = cs.CSClient().get("zenspace/pin_auth");

        auth_list = auth.get("data");

        if auth_list != None:

            for pins in auth_list:

                for x in pins.keys():
                    totalPins_gA.append(x);



        accessCodes=[];
        if zreskv.__len__() != 0:
            for res in zreskv:
                count=count+1;

                data = ''
                if "security_access_code__c" in res.keys() and "reservation_start_datetime__c" in res.keys() and "reservation_end_datetime__c" in res.keys():
                    accessPin=res.get("security_access_code__c")

                    if accessPin != "null":

                        data = {res.get("reservation_start_datetime__c").replace('T', ''): {
                            "pin": accessPin ,
                            "TimeOut": res.get("reservation_end_datetime__c").replace('T', '')}}

                        if accessPin not in totalPins_gA:
                            s=cs.CSClient().put("zenspace/pin_auth/"+str(count), data)
                            log.debug("result for pin put -- {}".format(s))
                        accessCodes.append(res.get("security_access_code__c"))


            if pin in accessCodes:

                return verifyAuth(pin)
            else:

                return 1

        else:

            return 1
    except Exception as e:
        log.debug("exception raised in getAuth()---{}".format(e))
        return 1
def get_iot_ip():

        global iot_ip
        if iot_ip == '':
            dhcpReserve = cs.CSClient().get('/config/dhcpd/reserve')

            dhcpReserveList = dhcpReserve.get("data")
            s = {}
            if dhcpReserveList != None:

                for drl in dhcpReserveList:
                    s.update(drl)
                    if "hostname" in s.keys() and "ip_address" in s.keys():

                        if (s.get("hostname") == "ZENIOTGATEWAY"):

                            iot_ip = s.get("ip_address")




            else:
               log.debug('iot ip is unavailable')
            log.debug("iot ip ={}".format(iot_ip))
            device_list(0)



            sensor_status(0)

        else:
            print("iot ip is present")


#Timer functions
def call_at_interval(period, callback, args):
    while True:
        sleep(period)
        callback(*args)
def setInterval(period, callback, *args):
    Thread(target=call_at_interval, args=(period, callback, args)).start()


def setTimeoutMinutes(minutes,callback,*args):
    seconds=minutes*60
    t = Timer(seconds, callback,args=(args))
    t.start()

def setTimeout(seconds,callback,*args):
    t = Timer(seconds, callback,args=(args))
    t.start()


mqtt_client = mqtt.Client(client_id=pod_id, protocol=mqtt.MQTTv311)


# Assign the appropriate callback functions
mqtt_client.on_connect = on_connect
mqtt_client.on_disconnect = on_disconnect
mqtt_client.on_publish = on_publish
mqtt_client.on_message = on_message
mqtt_client.on_subscribe = on_subscribe



try:
   get_iot_ip()
   set_state_color()

   if iot_hub_name !=None and pod_key !=None and pod_id !=None:
    mqtt_client.username_pw_set(username=iot_hub_name + '.azure-devices.net/' + pod_id+'/api-version=2018-06-30', password=generate_sas_token(iot_hub_name+".azure-device.net/devices"+pod_id,pod_key,pod_id))

    mqtt_client.tls_set(ca_certs=path_to_root_cert, certfile=None, keyfile=None, cert_reqs=ssl.CERT_REQUIRED,
                        tls_version=ssl.PROTOCOL_TLSv1, ciphers=None)

    mqtt_client.tls_insecure_set(False)

    log.debug("Connecting to hub")
    # mqtt_client.connect(iot_hub_name + '.azure-devices.net', port=8883)

    _thread.start_new_thread(mqtt_client.connect,(iot_hub_name+'.azure-devices.net',8883,))
    log.debug("hub connected")

    #request id to cloud
    grid='1000'
    log.debug("initial pod state {}".format(podState))
    mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + grid,
                        "{\"pod_state\":\"" + podState + "\"}",
                        qos=0)
    inform_pod_state()

    if iot_ip == '' :
        mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + grid,
                            "{\"gateway_status\":\"" + "No gateway detected" + "\"}", qos=0)
    else:
        start=0
        total_devices=get_number_of_devices()

        network_stats()
        gateway_status()

        device_list(start)
        if len(deviceslistbyid) == 0:
            pass
        else:
            old_devicelistbyid = deviceslistbyid.copy()
            setInterval(DEVICE_TIMER+120, device_list_manage)


        sensor_status(start)
        pod_status()
        setInterval(DEVICE_TIMER, device_list,start)
        setInterval(POD_TIMER, pod_status)
        setInterval(GATEWAY_TIMER,gateway_status)
        setInterval(SENSOR_TIMER,sensor_status,start)
        setInterval(CONN_TIMER,network_stats)
        setInterval(GATEWAY_TIMER,get_iot_ip)
    _thread.start_new_thread(start_server, ())

    mqtt_client.loop_forever()
   else:
       log.error("Hub Name,Pod Id,Pod Key is missing")





except Exception as e:
    log.error('Exception: {}'.format(e))




	
			
			

