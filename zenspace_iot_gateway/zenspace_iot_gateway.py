
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
# from http.server import HTTPServer, BaseHTTPRequestHandler
from server import HTTPServer, BaseHTTPRequestHandler
from paho.mqtt import client as mqtt
import cs
import settings
from app_logging import AppLogger
import _thread
import re

#Timers for reporting status to cloud in seconds
GATEWAY_TIMER=300
POD_TIMER=60
SENSOR_TIMER=60
DEVICE_TIMER=350
CONN_TIMER=12000
DESIRED_TIMER=10
HEALTH_TIMER=1800
POD_OFFLINE_TIMER=300
LOCK_TIMER=1
URL_TIMEOUT=40
CHANGE_TO_STATE_COLOR_TIMER=30
SENSOR_OFFLINE_TIMER=900
INTURSION_CHECK_TIMER=900
cameraKeepAliveTimer=30
unlockKeepAliveTimer=3600
zenspaceKeepAliveTimer=30
#Global variable
log = AppLogger()
devicelist={};
deviceslistbyid={};
devicestatus={};
devicestatuswithoutrx={};
devicestatustemp={};
old_devicelistbyid={};
total_devices='';
zenurl=settings.ZEN_URL
iot_ip=''
reservePodState='Unknown'
podState='Unknown';
prePodState='Unknown'
prevPodState='';
cloudPodState="Unknown";
beforeChangePodState=''
AVAILCOLOR=''
RESERVECOLOR=''
TIMEOUTCOLOR=''
ADMININUSECOLOR=''
RESERVEINUSECOLOR=''
AVAILINBLINK=''
RESERVEINBLINK=''
LIGHTLEV=75
beforePodState='Unknown'
state="enabled"
lockstate="enabled"
offline=0
lightLevTemp={"level":100,"colorTemp":153}
colorTemp=0
colorSat=0
colorHue=0
lightState="Unknown"
lightColor="Unknown"
doorState="Unknown"
teamViewerState="false"
zensapceState="false"
airServerState="false"
tmpState=''
lightLevel=0
healthFlag=0
group_id=0
cloudbeforePodState="Unknown"
fanState="enabled"
intruderState="enabled"
mqtt_flag=0
tdflag=0
tdevent=20
sensorOffline=[]
unreachable_host = []
offlineDevices=[];
intrusionDetection=0;
intrusion=[];
grpmembers=[];
conn_type=""
cpOnlineTime=datetime.datetime.utcnow().replace(microsecond=0)
ppOnlineTime=datetime.datetime.utcnow().replace(microsecond=0)
intrusionDetectionTime=datetime.datetime.utcnow().replace(microsecond=0)
unlockKeepAlive= datetime.datetime.utcnow().replace(microsecond=0)
zenspaceKeepAlive=datetime.datetime.utcnow().replace(microsecond=0)
cameraKeepAlive=datetime.datetime.utcnow().replace(microsecond=0)
#set light state as enabled intitally

ports=settings.PORTS

#Header for gateway request.
headers = {}
headers['content-type'] = 'application/json'

#IOT gateway url
url="http://"
zen_state_url=settings.ZEN_STATE_URL
logicUrl=settings.ZEN_LOGICALNAME_URL

# Path to the TLS certificates file. The certificates were copied from the certs.c file
# located here: https://github.com/Azure/azure-iot-sdk-c/blob/master/certs/certs.c
path_to_root_cert = os.path.join(os.getcwd(), 'certs.cer')

#Get hubname,podid,podkey from router
hubName__j=cs.CSClient().get('/config/system/asset_id')
podId__j=cs.CSClient().get('/config/system/system_id')
podKey__j=cs.CSClient().get('/config/system/desc')

cs.CSClient().put("/control/ping/start/host","")
cs.CSClient().put("/control/ping/start/size",64)
cs.CSClient().put("/control/ping/start/num",4)

iot_hub_name="Unknown"
pod_id="Unknown"
pod_key="Unknown"
ports=settings.PORTS


# MS Azure IoT Hub name
# iot_hub_name='zenhub'
if hubName__j != None:
    iot_hub_name=hubName__j.get("data")
# Device name in MS Azure IoT Hub
if podId__j != None:
    pod_id=podId__j.get("data")
# SAS token for the device id. This can be generated using the Device Explorer Tool.
# The format of the token should be similar to:
# 'SharedAccessSignature sr={your hub name}.azure-devices.net%2Fdevices%2FMyDevice01%2Fapi-version%3D2016-11-14&sig=vSgHBMUG.....Ntg%3d&se=1456481802'
if podKey__j != None:
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
    global state,AVAILCOLOR,RESERVECOLOR,TIMEOUTCOLOR,ADMININUSECOLOR,RESERVEINUSECOLOR,AVAILINBLINK,RESERVEINBLINK,group_id,tmpState


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
    try:
        res = urllib.request.urlopen(url + iot_ip + '/groups',timeout=URL_TIMEOUT)
        gres = res.read()
        group_response = json.loads(gres)
        if "groups" in group_response.keys():
            g=group_response.get("groups")
            if "list" in g.keys():
                group_list = group_response.get("groups").get("list")
                for keys in group_list:

                    if keys.get('name') == 'demo lights':
                        group_id = keys.get('groupId')

    except Exception as e:
        log.debug("Exception raises in set_state_color {}".format(e))

#Get group info
def group():
    global group_id,groupnames,gnflag,offlineDevices
    gnames=[]
    try:
        res = urllib.request.urlopen(url + iot_ip + '/groups', timeout=URL_TIMEOUT)
        gres = res.read()
        group_response = json.loads(gres)
        group_list = group_response.get("groups").get("list")

        for keys in group_list:
            gnames.append(keys.get('name'))
            if keys.get('name') == 'demo lights':
                group_id = keys.get('groupId')
                locationid=keys.get('locationId')
                if locationid > 1:
                    if "demolocation" in offlineDevices:
                        offlineDevices.remove("demolocation")
                        log.debug("light group location id is greater than 1")
                else:
                    if "demolocation" in offlineDevices:
                        pass
                    else:
                        offlineDevices.append("demolocation")
                        # data = {"lightgroup": "Group for light is miscommisioned"}
                        # mqtt_client.publish('devices/' + pod_id + '/messages/events/', json.dumps(data).encode('utf-8'),
                        #                     qos=1)
                        data={"type":"CRITICAL","deviceType":"sensor","name":"light group","message":{"status":"Group for light is miscommisioned"}}
                        mqtt_client.publish('devices/' + pod_id + '/messages/events/', json.dumps(data),
                                            qos=1)
        if "demo lights" not in gnames:
            log.debug("group is not present")
            if "demo" in offlineDevices:
                pass
            else:
                log.debug("publish the group is not commisioned");
                offlineDevices.append("demo")
                # data={"lightgroup":"Group for light is not commisioned"}
                # mqtt_client.publish('devices/' + pod_id + '/messages/events/', json.dumps(data).encode('utf-8'), qos=1)
                data = {"type": "CRITICAL", "deviceType": "sensor", "name": "light group",
                        "message": {"status":"Group for light is not commisioned"}}
                mqtt_client.publish('devices/' + pod_id + '/messages/events/', json.dumps(data), qos=1)
        else:
            log.debug("group is present ")
            if "demo" in offlineDevices:
                offlineDevices.remove("demo")

    except Exception as e:
        log.debug("Exception raises in set_state_color {}".format(e))


#Rule engine.Based on podState and state table provided by zenspace,it will change the state of sensors
def group_light_change(colorcode):
   global LIGHTLEV,group_id,podState,intrusionDetection
   if podState == "Reservation In Use" or podState == "Admin In Use":
       intrusionDetection =0

   log.debug("on group light change ")
   try:
        dat = {"on": "true", "color": colorcode,"level":LIGHTLEV}
        data = json.dumps(dat).encode('utf-8')
        log.debug("Group color data is {} -- id - {}".format(data,group_id))

        req = urllib.request.Request(url + iot_ip + '/groups/id/' + str(group_id),
                                     headers=headers, data=data,
                                     method="PUT")
        resp = urllib.request.urlopen(req,timeout=URL_TIMEOUT)
   except Exception as e:
       log.debug("Exception changing Group color {}".format(e))

def trigger_group_light_change(colorcode):
   global group_id,podState,intrusionDetection
   log.debug("on trigger group light change ")
   if podState == "Reservation In Use" or podState == "Admin In Use":
       intrusionDetection = 0

   try:
        tdat = {"on": "true", "color": colorcode}

        tdata = json.dumps(tdat).encode('utf-8')
        # log.debug("Group color data is {} -- id - {}".format(tdata,group_id))

        req = urllib.request.Request(url + iot_ip + '/groups/id/' + str(group_id),
                                     headers=headers, data=tdata,
                                     method="PUT")
        resp = urllib.request.urlopen(req,timeout=URL_TIMEOUT)
   except Exception as e:
       log.debug("Exception changing Group color on trigger {}".format(e))


def group_blink(blinkcount):
   global group_id
   try:
       count = 1
       while count <= blinkcount:
            dat = {"on": "false"}
            data = json.dumps(dat).encode('utf-8')
            log.debug("Group color data is {},group id -{}".format(data,group_id))

            req = urllib.request.Request(url + iot_ip + '/groups/id/' + str(group_id),
                                         headers=headers, data=data,
                                         method="PUT")
            resp = urllib.request.urlopen(req,timeout=URL_TIMEOUT)
            dat = {"on": "true"}
            data = json.dumps(dat).encode('utf-8')


            req = urllib.request.Request(url + iot_ip + '/groups/id/' + str(group_id),
                                         headers=headers, data=data,
                                         method="PUT")
            resp = urllib.request.urlopen(req,timeout=URL_TIMEOUT)
            count = count + 1


   except Exception as e:
       log.debug("Exception blinking Group color {}".format(e))


def redblink():
   global grpmembers,intrusionDetection
   try:
       log.debug(" Inside red blink -{}".format(grpmembers))
       if len(grpmembers) == 0:
           res = urllib.request.urlopen(url + iot_ip + '/groups/id/' + str(group_id), timeout=URL_TIMEOUT)
           group = json.loads(res.read())
           print(group)
           if "group" in group.keys():
               gr = group.get("group")
               if gr != None:
                   grpmembers = gr.get("list")
                   log.debug(" Group members-{}".format(grpmembers))

       while (True):
             if intrusionDetection == 1:
                #group_blink(1)
                 identify_blink()
             else:

                 break
             sleep(8)

   except Exception as e:
       log.debug("Exception red blinking Group color {}".format(e))



def identify_blink():
            global grpmembers
            log.debug("Inside identify blink -{}".format(grpmembers))
            dat = {"command": "identify", "duration": 5}
            body = json.dumps(dat).encode('utf-8')
            for i in grpmembers:
                print(i)
                try:
                    req = urllib.request.Request(url + iot_ip + '/devices/' + i,headers=headers, data=body, method="PUT")
                    resp = urllib.request.urlopen(req, timeout=URL_TIMEOUT)
                    log.debug( " Response is -{}".format(resp))

                except Exception as e:
                    log.debug("Exception in identify blink -{}".format(e))










def update_pod_state():
    global podState,iot_ip,state
    global AVAILCOLOR, RESERVECOLOR, TIMEOUTCOLOR, ADMININUSECOLOR, RESERVEINUSECOLOR, AVAILINBLINK, RESERVEINBLINK
    log.debug("update pod state is -- {},light state is - {}".format(podState,state))
    if podState == "Available":
        group_light_change(AVAILCOLOR)
        try:
            for k, v in devicelist.items():

                if ("fan" in k):
                    id = v[0];

                    # dat = {"on": "false"}
                    dat = {"on":"true"}
                    data = json.dumps(dat).encode('utf-8')
                    req = urllib.request.Request(url+iot_ip + '/devices/' + id,
                                                 headers=headers, data=data,
                                                 method="PUT")
                    resp = urllib.request.urlopen(req,timeout=URL_TIMEOUT)
        except Exception as e:
               log.debug("Exception raises in updatepodstate - {}".format(e))
    elif podState == "Reserved":
        group_light_change(RESERVECOLOR)
        try:
            for k, v in devicelist.items():

                if ("fan" in k):

                        id = v[0];
                        # dat = {"on": "false"}
                        dat = {"on": "true"}
                        data = json.dumps(dat).encode('utf-8')
                        req = urllib.request.Request(url+iot_ip + '/devices/' + id,
                                                     headers=headers, data=data,
                                                     method="PUT")
                        resp = urllib.request.urlopen(req,timeout=URL_TIMEOUT)
        except Exception as e:
            log.debug("Exception raises in updatepodstate - {}".format(e))
    elif podState == "Admin In Use":
        group_light_change(ADMININUSECOLOR)
        try:
            for k, v in devicelist.items():


                if ("fan" in k):

                        id = v[0];
                        # dat = {"on": "true"}
                        dat = {"on": "true"}
                        data = json.dumps(dat).encode('utf-8')
                        req = urllib.request.Request(url+iot_ip + '/devices/' + id,
                                                     headers=headers, data=data,
                                                     method="PUT")
                        resp = urllib.request.urlopen(req,timeout=URL_TIMEOUT)
        except Exception as e:
                 log.debug("Exception raises in updatepodstate - {}".format(e))
    elif podState == "Reservation In Use":
        group_light_change(RESERVEINUSECOLOR)
        try:
            for k, v in devicelist.items():
                if ("fan" in k):
                    id = v[0];
                    # dat = {"on": "true"}
                    dat = {"on": "true"}
                    data = json.dumps(dat).encode('utf-8')
                    req = urllib.request.Request(url+iot_ip + '/devices/' + id,
                                                 headers=headers, data=data,
                                                 method="PUT")
                    resp = urllib.request.urlopen(req,timeout=URL_TIMEOUT)
        except Exception as e:
            log.debug("Exception raises in update pod state-{}".format(e))
    elif podState == "TimeOut":
        group_light_change(TIMEOUTCOLOR)
        try:
            for k, v in devicelist.items():
                if ("fan" in k):
                    id = v[0];
                    # dat = {"on": "true"}
                    dat = {"on": "true"}
                    data = json.dumps(dat).encode('utf-8')
                    req = urllib.request.Request(url+iot_ip + '/devices/' + id,
                                                 headers=headers, data=data,
                                                 method="PUT")
                    resp = urllib.request.urlopen(req,timeout=URL_TIMEOUT)
        except Exception as e:
            log.debug("Exception raises in update pod state - {}".format(e))
    elif podState == "Available in Next 10 min":
        if AVAILINBLINK == 0:
            group_light_change("white")
        group_blink(AVAILINBLINK)
        try:
            for k, v in devicelist.items():
                if ("fan" in k):
                    id = v[0];
                    # dat = {"on": "true"}
                    dat = {"on": "true"}
                    data = json.dumps(dat).encode('utf-8')
                    req = urllib.request.Request(url+iot_ip + '/devices/' + id,
                                                 headers=headers, data=data,
                                                 method="PUT")
                    resp = urllib.request.urlopen(req,timeout=URL_TIMEOUT)
        except Exception as e:
            log.debug("Exception raises in update pod state - {}".format(e))
    elif podState == "Unknown":
        group_light_change("white")
        try:
            for k, v in devicelist.items():

                if ("fan" in k):
                    id = v[0];
                    # dat = {"on": "true"}
                    dat = {"on": "true"}
                    data = json.dumps(dat).encode('utf-8')
                    req = urllib.request.Request(url+iot_ip + '/devices/' + id,
                                                 headers=headers, data=data,
                                                 method="PUT")
                    resp = urllib.request.urlopen(req,timeout=URL_TIMEOUT)
        except Exception as e:
            log.debug("Exception raises in update pod state - {}".format(e))
    elif podState == "Reserved in Next 10 min":
        if RESERVEINBLINK == 0:
            group_light_change("white")
        group_blink(RESERVEINBLINK)
        try:
            for k, v in devicelist.items():
                if ("fan" in k):
                    id = v[0];
                    # dat = {"on": "true"}
                    dat = {"on": "true"}
                    data = json.dumps(dat).encode('utf-8')
                    req = urllib.request.Request(url+iot_ip + '/devices/' + id,
                                                 headers=headers, data=data,
                                                 method="PUT")
                    resp = urllib.request.urlopen(req)
        except Exception as e:
            log.debug("Exception raises in update pod state - {}".format(e))
    sensor_status_publish()

#Update pod state to salesforce
def inform_pod_state():
    global podState
    dat = {"state":podState}
    headers={"Content-Type":"application/x-www-form-urlencoded"}
    try:
        data = urllib.parse.urlencode(dat).encode('utf-8')
        req = urllib.request.Request(zen_state_url + pod_id + "/", headers=headers, data=data, method="POST")
        resp = urllib.request.urlopen(req,timeout=URL_TIMEOUT)
        log.debug("informing pod state to salsesforce -- {} ".format(podState))



    except Exception as e:
        log.debug("Exception raised in inform_pod_state-- {}".format(e))

        mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + grid,
                            "{\"pod_state\":\"" + podState + "\"}",
                            qos=1)

#Change pod state after admin tmieout.When state is "Admin In Use",state pushed by cloud is hold.After "Admin Timeout" ,the cloud pushed state is replaced.If cloud doesnot push any state ,in between "Admin In Use" and "Admin TmeOut",the previous state maintained by cradlepoint will be replaced.
def change_prev_pod_state():
    global podState,prevPodState,cloudPodState,tmpState,beforePodState,cloudbefore,prePodState
    log.debug("changing pod state after admin timeout")

    try:
        if tmpState == "Reservation in Use":
            log.debug("tmpState is Reservation in use")
            tmpState= ""
        else:
            # if cloudPodState == '' or cloudPodState == None:
            if cloudPodState == "Unknown":
                    prePodState=podState
                    podState=prevPodState

            else:
                prePodState = podState
                podState = cloudPodState


                if cloudPodState == "Reserved in Next 10 min" or cloudPodState == "Available in Next 10 min":
                    log.debug("R10 or A10")
                    if cloudbeforePodState == "Reserved":
                        log.debug("R10 or A10 & cbp - Reserved")
                        group_light_change(RESERVECOLOR)
                    elif cloudbeforePodState == "Available":
                        log.debug("R10 or A10 & cbp - Available")
                        group_light_change(AVAILCOLOR)
                cloudPodState = "Unknown"



            log.debug("applying pod State --- {} ".format(podState))
            mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + grid,
                                    "{\"pod_state\":\"" +podState + "\"}",
                                    qos=1)

            update_pod_state()
            #commented out inform pod state since zazi would have updated salesforce
            #inform_pod_state()
            # sensor_status(0)
            sensor_status_publish()
    except Exception as e:
        log.debug("Exception raises in change prevposState - {}".format(e))


#To change pod state,update pod state to cloud and sales force
def change_pod_state(state):

    global podState,prePodState
    try:
        if( podState == "Admin In Use"):
            log.debug("Reservation Timeout is bypassed,because pod used by Admin")
        else:
            prePodState = podState
            podState=state
            mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + grid,
                                "{\"pod_state\":\"" + podState + "\"}",
                                qos=1)
            update_pod_state()
            # sensor_status(0)
            sensor_status_publish()
            inform_pod_state()
    except Exception as e:
        log.debug("Exception raises in change pod state - {}".format(e))

def apply_logical_ssid(logicalName):
    log.debug("apply logical ssid")

    try:
        i = 0;


        lan = cs.CSClient().get('/config/lan');
        wlan_radio = cs.CSClient().get('/config/wlan/radio')
        radios = wlan_radio.get("data");
        lan_interfaces = lan.get("data");
        print(lan)
        print(wlan_radio)
        print(radios)
        print(lan_interfaces)
        num_lan_interfaces = lan_interfaces.__len__();
        for inter in lan_interfaces:
            # print(inter.__getitem__('name'))

            print(i)
            if (inter.__getitem__('route_mode') == "hotspot"):
                print(inter.__getitem__('name'))
                dev_path = '/config/lan/' + str(i) + '/devices'

                dev = cs.CSClient().get(dev_path);

                devices = dev.get("data");

                for s in devices:
                    type = s.__getitem__('type')
                    uid = s.__getitem__('uid')

                    j = 0


                    if (type != "ethernet"):
                        print(type, ": ", uid)
                        for r in radios:
                            bss = r.__getitem__('bss');

                            k = 0;
                            for bs in bss:

                                bss_uid = bs.__getitem__('uid')
                                print("bss _uid {}".format(bss_uid))

                                if (bss_uid == uid):
                                    print(bs.__getitem__('uid'))
                                    print("radio =", j, "  bss= ", k)
                                    cs.CSClient().put('/config/wlan/radio/' + str(j) + '/bss/' + str(k) + '/ssid',
                                                      logicalName)


                                else:
                                    # print("rest were private ssid")
                                    if (j == 0):
                                        print("radio =", j, "  bss= ", k)

                                k = k + 1;
                            j = j + 1;

            i = i + 1;
    except Exception as e:
        log.debug("Exception raised in apply logical ssid -- {}".format(e))
def sync_logical_ssid():
    global pod_id,logicUrl

    try:
        log.debug("Syncing logical ssid ")
        localdate=datetime.datetime.now().date()
        res = urllib.request.urlopen(logicUrl + pod_id + "/?localdate=" + str(localdate), timeout=URL_TIMEOUT)
        # print(res.read())
        data = json.loads(res.read())
        print(data)
        if "result" in data.keys():
            print(data.get("result"))
            logicalName = data.get("result")[0].get("name")
            apply_logical_ssid(logicalName)
        else:
            print("Logical pod name is not defined")
    except Exception as e:
        log.debug("Exception raised in sync logical ssid {}".format(e))

def on_log(client,userdata,level,buf):
     # log.debug("mqtt connection - {}".format(buf))
     pass


# Called when the broker responds to our connection request.
def on_connect(client, userdata, flags, rc):
    log.info("on connect")
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
        setTimeout(DESIRED_TIMER,get_desired)


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
    pass
    # log.info('Device sent message {} '.format(mid))

    


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
    global iot_ip,cloudPodState,state,lockstate,cloudbeforePodState,beforePodState,intruderState,intrusionDetection
    global podState,lightState,LOCK_TIMER,prePodState
    global DESIRED_TIMER,DEVICE_TIMER,GATEWAY_TIMER,POD_TIMER,SENSOR_TIMER,CONN_TIMER

    log.debug('Device received topic: {}, msg: {}'.format(msg.topic, str(msg.payload.decode("utf-8"))))
    topic=msg.topic;

    req_body={};
    publish_response={};
    # try:
    if "$iothub/twin/res/200/?$rid=101" in topic:
        try:
            log.debug("reading desired properties")
            msgDecode = str(msg.payload.decode('utf-8'))
            msgToJson = json.loads(msgDecode)
            if "desired" in msgToJson.keys():
                print(msgToJson)
                desired = msgToJson.get("desired")

                if "pod_state" in desired.keys():
                    prePodState=podState
                    beforePodState = podState
                    log.debug("pod state updated by {}".format(podState))
                    log.debug("on message first,cloud before pod state -- {} ,cloud state is -- {}".format(cloudbeforePodState,cloudPodState))
                    if cloudPodState != None or cloudPodState != '':
                        cloudbeforePodState = cloudPodState
                    cloudPodState = desired.get("pod_state")

                    log.debug("on message ,cloud before pod state -- {} ,cloud state is -- {}".format(cloudbeforePodState,
                                                                                                cloudPodState))
                    log.debug("pod state is {}".format(desired.get("pod_state")))
                    if podState == "Admin In Use":
                        pass
                    elif podState == "Reservation In Use" and desired.get("pod_state") == "Reserved":
                        pass
                    elif desired.get("pod_state") == "Reserved in Next 10 min" or desired.get("pod_state") == "Available in Next 10 min":
                        log.debug("pod state R10 or A10")
                        if beforePodState == "Reservation In Use":
                            log.debug("prev pod state is RIU,updating state")

                        else:
                            log.debug("pod state is R10 or A10 but pod not in use")
                            pass
                    else:
                        podState=desired.get("pod_state")
                        update_pod_state()
                    mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + grid,
                                        "{\"pod_state\":\"" + podState + "\"}",
                                        qos=1)
                if "ssid_reset" in desired.keys():
                    sreset=desired.get("ssid_reset")
                    if sreset.lower() == "yes":
                        sync_logical_ssid()
                    else:
                        pass
                if "light_state" in desired.keys():
                    state=desired.get("light_state")
                    mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + grid,
                                        "{\"light_state\":\"" + state + "\"}",
                                        qos=1)
                    set_state_color()
                    update_pod_state()
                if "lock_state" in desired.keys():
                    lockstate = desired.get("lock_state")
                    if lockstate == "disabled":
                        unlock_door()
                    mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + grid,
                                        "{\"lock_state\":\"" + lockstate + "\"}",
                                        qos=1)
                if "intruder_state" in desired.keys():
                    intruderState=desired.get("intruder_state")
                    if intruderState == "disabled":
                        intrusionDetection =0
                        log.debug(" Intruder state in desired properties")
                        change_to_state_color(0)
                    mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + grid,
                                        "{\"intruder_state\":\"" + intruderState + "\"}",
                                        qos=1)
                if "fan_state" in desired.keys():
                    fanState=desired.get("fan_state")
                    mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + grid,
                                        "{\"fan_state\":\"" + fanState + "\"}",
                                        qos=1)
                if "timers" in desired.keys():
                    log.debug("timers change")
                    timers = desired.get("timers")
                    if "lock_timer" in timers.keys():
                        LOCK_TIMER = timers.get("lock_timer");
                        mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + grid,
                                            "{\"timers\": { \"lock_timer\":\"" + str(LOCK_TIMER) + "\"}}",
                                            qos=1)

                if "pin_auth" in desired.keys():
                    re = cs.CSClient().delete('zenspace/pin_auth')
                    y=desired.get("pin_auth")
                    try:
                        au = json.dumps(y)
                        count = 0
                        for k, v in y.items():
                            # data={k:{"TimeIn":v.get("TimeIn"),"TimeOut":v.get("TimeOut")}}
                            data = {k: {"pin": v.get("pin"), "TimeOut": v.get("TimeOut")}}
                            s = cs.CSClient().put('zenspace/pin_auth/' + str(count), data)

                            count = count + 1
                        data = cs.CSClient().get("zenspace/").get("data")

                        print(data)
                        try:
                            if os.path.exists('/var/media'):
                                log.debug("media exists - on message")
                                with open("/var/media/auth.ini", 'w+', encoding='utf-8') as f:
                                    if data == None:
                                        d = {}
                                        json.dump(d, f)
                                    else:
                                        json.dump(data, f)

                                f.close()
                            else:
                                log.debug("media not exists - on message")
                        except Exception as e:
                            log.debug("Unable to write into flash {}".format(e))

                        # s=cs.CSClient().post('zenspace/auth',au)

                    except Exception as e:
                        log.debug("exception in saving the pin {}".format(e))
                if "admin_auth" in desired.keys():
                    re = cs.CSClient().delete('zenspace/admin_auth')

                    try:
                        y=desired.get("admin_auth")
                        au = json.dumps(y)
                        # log.debug("admin _auth pin -{} = {} ".format(y))
                        count = 0
                        for k, v in y.items():
                            data = {k: v}

                            # s = cs.CSClient().post('zenspace/admin_auth/', data)
                            s = cs.CSClient().put('zenspace/admin_auth/' + str(count), data)

                            count = count + 1
                        data = cs.CSClient().get("zenspace/").get("data")

                        print(data)
                        try:
                            if os.path.exists('/var/media'):
                                log.debug("media exists - on message")
                                with open("/var/media/auth.ini", 'w+', encoding='utf-8') as f:
                                    if data == None:
                                        d = {}
                                        json.dump(d, f)
                                    else:
                                        json.dump(data, f)

                                f.close()
                            else:
                                log.debug("media not exists - on message")
                        except Exception as e:
                            log.debug("Unable to write into flash {}".format(e))

                        # s=cs.CSClient().post('zenspace/auth',au)

                    except Exception as e:
                        log.debug("exception in saving the pin {}".format(e))

        except Exception as e:
            log.debug("Exception raises in processing read desired properties -{}".format(e))

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

                        count=count+1
                    data = cs.CSClient().get("zenspace/").get("data")

                    print(data)
                    try:
                        if os.path.exists('/var/media'):
                            log.debug("media exists - on message")
                            with open("/var/media/auth.ini", 'w+', encoding='utf-8') as f:
                                if data == None:
                                    d = {}
                                    json.dump(d, f)
                                else:
                                    json.dump(data, f)

                            f.close()
                        else:
                            log.debug("media not exists - on message")
                    except Exception as e:
                        log.debug("Unable to write into flash {}".format(e))

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

                        # s = cs.CSClient().post('zenspace/admin_auth/', data)
                        s = cs.CSClient().put('zenspace/admin_auth/'+str(count), data)

                        count=count+1
                    data = cs.CSClient().get("zenspace/").get("data")

                    print(data)
                    try:
                        if os.path.exists('/var/media'):
                            log.debug("media exists - on message")
                            with open("/var/media/auth.ini", 'w+', encoding='utf-8') as f:
                                if data == None:
                                    d = {}
                                    json.dump(d, f)
                                else:
                                    json.dump(data, f)

                            f.close()
                        else:
                            log.debug("media not exists - on message")
                    except Exception as e:
                        log.debug("Unable to write into flash {}".format(e))

                    # s=cs.CSClient().post('zenspace/auth',au)

                except Exception as e:
                    log.debug("exception in saving the pin {}".format(e))
            elif x == "pod_state":
                prePodState = podState
                beforePodState=podState
                log.debug("pod state updated by {}".format(podState))
                log.debug("on message first,cloud before pod state -- {} ,cloud state is -- {}".format(cloudbeforePodState,
                                                                                                  cloudPodState))
                if cloudPodState != None or cloudPodState!='':

                    cloudbeforePodState = cloudPodState
                cloudPodState=y

                log.debug("on message ,cloud before pod state -- {} ,cloud state is -- {}".format(cloudbeforePodState,cloudPodState))
                if podState == "Admin In Use":
                    log.debug(" Admin In use,cloud pushed state is by passed")
                    pass
                else:
                    prePodState = podState
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
                                    qos=1)
            elif x == "ssid_reset":
                sreset = y
                if sreset == "yes":
                    sync_logical_ssid()
                else:
                    pass
            elif x == "lock_state":

                lockstate = y
                mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + grid,
                                    "{\"lock_state\":\"" + lockstate + "\"}",
                                    qos=1)
            elif x == "health_monitor":
                if y == "yes":
                    try:
                        health_monitoring()
                    except Exception as e:
                        log.debug("Exception raised in processing health monitoring {}".format(e))
            elif x == "fan_state":

                fanState = y
                mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + grid,
                                    "{\"fan_state\":\"" + fanState + "\"}",
                                    qos=1)
            elif x == "intruder_state":
                intruderState = y
                #12/11/2019 fix for Disable intruder
                if intruderState == "disabled":
                    intrusionDetection =0
                    log.debug(" Intruder state on message")
                    change_to_state_color(0)
                #############################
                mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + grid,
                                    "{\"intruder_state\":\"" + intruderState + "\"}",
                                    qos=1)

            elif x == "light_state":

                state=y
                mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + grid,
                                    "{\"light_state\":\"" + state + "\"}",
                                    qos=1)
                set_state_color()
                update_pod_state()
            elif x == "timers":
                log.debug("timers change")
                timers=y
                if "lock_timer" in y.keys():
                    LOCK_TIMER=y.get("lock_timer");
                    mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + grid,
                                        "{\"timers\": { \"lock_timer\":\"" + str(LOCK_TIMER) + "\"}}",
                                        qos=1)



            elif devicelist.__contains__(x):
                try:
                    id=devicelist.__getitem__(x)[0]

                    data = json.dumps(y).encode('utf-8')
                    log.debug("data is {}".format(data))

                    req=urllib.request.Request(url+iot_ip+'/devices/'+id,headers=headers,data=data,method="PUT")
                    resp = urllib.request.urlopen(req,timeout=URL_TIMEOUT)
                    log.debug("response from gateway -- {}".format(resp))


                    # single_sensor_status(id)
                    start=0
                    # sensor_status(start)

                    sensor_status_publish()
                    log.debug("x is  {}  and y is {}".format(x,y))
                    if x == "door_lock" and "on" in y.keys():

                        val=y.get("on")
                        if lockstate == "enabled" and val.lower() == "false":
                            lock_door()
                    sensor_status_publish()

                except Exception as e:
                    log.debug("Exception - processing sensor configuration -- {}".format(e))
            else:
                log.debug("no such device - {}".format(x))


     except Exception as e:
         log.error("Exception occurs in message processing /properties/desired-{}".format(e))

#Note:sensor status and device list functions are recurssion function because at a given time IOT gateway responds as it can.

#Getting the gateway status from IOT gateway api and twin property reported to cloud

def gateway_status():
    global iot_ip
    res='';
    try:
        res=urllib.request.urlopen(url+iot_ip+'/gateway',timeout=URL_TIMEOUT)
        gres=res.read()
        gateway_response= json.loads(gres)
        status=gateway_response.get("gateway").get("info").get("state")

    except Exception as ex:
        log.debug('gateway not reachable-{}'.format(ex))
        status="Not connected"

    try:
        mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + grid,
                        "{\"gateway_status\":\"" + status + "\"}", qos=1)
        currentdate=datetime.datetime.now().date()
        mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + dt,
                            "{\"local_date\":\"" + str(currentdate) + "\"}",
                            qos=1)
        # log.info('Gateway status published')
    except Exception as e:
        log.debug('Gateway status not publidhed - {}'.format(e))







#Current local time of the cradle point is treated as pod keep-alive time.
def pod_status():
    # currenttime = time.asctime(time.localtime(time.time()))
    try:
        log.debug("  Number of active threads == {}".format(active_count()))
        currenttime=str(datetime.datetime.utcnow().replace(microsecond=0))
        mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + grid,
                            "{\"pod_rxtime\":\"" + currenttime + "\"}", qos=1)

        # log.info('POD Status published')


        offline_online_check()
    except Exception as e:
        log.info('pod status not published {}'.format(e))


#Getting single sensor status
def single_sensor_status(sensor_id):
    global iot_ip
    try:
        srid="2000"
        response = urllib.request.urlopen(url+iot_ip + '/devices/status/'+sensor_id,timeout=URL_TIMEOUT)
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
                                        str(rep_prop), qos=1)
                    mqtt_client.publish('devices/' + pod_id + '/messages/events/', json.dumps(rep_prop), qos=1)

    except Exception as e:
        log.debug("Exception in single sensor status - {}".format(e))



def change_to_state_color(startIndex):

    global total_devices, iot_ip, podState, intrusionDetection, beforePodState, intrusionDetectionTime
    try:

        if (startIndex >= total_devices):
            # log.debug("change to state color ends")
            return 1
        srid = '4'
        log.debug("change to state color fucntion begins")
        #log.debug(" Start Index -{}  Total devices -{}".format(startIndex, total_devices))
        response = urllib.request.urlopen(url + iot_ip + '/devices/status?startIndex=' + str(startIndex),
                                          timeout=URL_TIMEOUT)
        respData = response.read();
        res = json.loads(respData)
        list = res.get("deviceStatus").get("list")
        count = 0
        for x in list:
            count = count + 1
            identifier = x.get("identifier")
            rxtime=x.get("rxTime")
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
                # log.debug("light color is {}  , state color {}".format(color,podState))
                cTime = datetime.datetime.utcnow().replace(microsecond=0)
                if cTime > intrusionDetectionTime:
                    diff = cTime - intrusionDetectionTime
                else:
                    diff = intrusionDetectionTime - cTime
                diffSeconds = diff.seconds;
                # log.debug("name -{} ,cTime - {} ,inTime - {} , diff - {}".format(name,cTime,intrusionDetectionTime,diffSeconds))
                if intrusionDetection == 1 and (podState == "Available" or podState == "Reserved") and int(
                        diffSeconds) < INTURSION_CHECK_TIMER:
                    log.debug("intrusion detected,don't trigger color change")
                    pass
                elif intrusionDetection == 1 and (
                        podState == "Available in Next 10 min" or podState == "Reserved in Next 10 min") and int(
                        diffSeconds) < INTURSION_CHECK_TIMER:
                    if beforePodState == "Available" :
                        log.debug("intrusion detected,don't trigger color change")
                        pass
                else:
                    log.debug("color change")
                    if podState == "Available" and color != AVAILCOLOR and rxtime !=0:
                        log.debug("trigger color change-available")
                        trigger_group_light_change(AVAILCOLOR)
                    elif podState == "Reserved" and color != RESERVECOLOR and rxtime !=0:
                        log.debug("trigger color change-reserved")
                        trigger_group_light_change(RESERVECOLOR)
                    elif podState == "Admin In Use" and color != ADMININUSECOLOR and rxtime!=0:
                        log.debug("trigger color change-admin in use")
                        trigger_group_light_change(ADMININUSECOLOR)
                    elif podState == "Reservation In Use" and color != RESERVEINUSECOLOR and rxtime !=0:
                        log.debug("trigger color change-reservation in use")
                        trigger_group_light_change(RESERVEINUSECOLOR)
                    elif podState == "TimeOut" and color != TIMEOUTCOLOR and rxtime !=0:
                        log.debug("trigger color change-timeout")
                        trigger_group_light_change(TIMEOUTCOLOR)



        # log.info('change to state color  ends')
        return change_to_state_color(startIndex + count)
    except Exception as e:
        log.debug("Processing sensor status fails {}".format(e))
        return 1


def sensor_status_check_only(startIndex):

   global total_devices,iot_ip,colorTemp,podState,intrusionDetection,beforePodState,intrusionDetectionTime,colorSat,colorHue,prePodState
   try:
       if (startIndex >= total_devices):

           return 1
       srid='4'


       response=urllib.request.urlopen(url+iot_ip + '/devices/status?startIndex='+str(startIndex),timeout=URL_TIMEOUT)
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
               rep_prop_rx = {}
               rep_status_rx = {};
               name = deviceslistbyid.__getitem__(identifier)[0];
               deviceType = deviceslistbyid.__getitem__(identifier)[1];
               mfg=deviceslistbyid.__getitem__(identifier)[2];
               model = deviceslistbyid.__getitem__(identifier)[2];

               rep_status.update({"deviceType": deviceType})
               rep_status.update({"mfg":mfg});
               rep_status.update({"model":model})
               rep_status_rx.update({"deviceType": deviceType})
               rep_status_rx.update({"deviceType": deviceType})
               rep_status_rx.update({"mfg": mfg});
               rep_status_rx.update({"model": model})

               for y, z in x.items():
                   if y == "rxTime":
                       rep_status.update({y: str(datetime.datetime.utcfromtimestamp(z))})
                       try:
                           current_rxtime=datetime.datetime.utcnow().replace(microsecond=0)
                           sensor_rxtime=datetime.datetime.utcfromtimestamp(z)
                           if current_rxtime > sensor_rxtime:
                               print("crxtime is greater")
                               diff = current_rxtime - sensor_rxtime
                           else:
                               print("sensor rxtime is greater")
                               diff = sensor_rxtime - current_rxtime


                           if(int(diff.seconds) >= SENSOR_OFFLINE_TIMER):
                               if name in sensorOffline:
                                 pass
                               else:
                                   if name == "" or str(name).__contains__(" "):
                                       pass
                                   else:
                                       log.debug("{} sensor unreachable".format(name))
                                       sensorOffline.append(name)
                                       nameAlert = name+"_alert"
                                       data = {"type": "WARNING", "deviceType": "sensor", "name": nameAlert,
                                               "message": {"status":"sensor unreachable" ,"Current_UTC":str(current_rxtime), "Sensor_UTC":str(sensor_rxtime)}
                                               }
                                       print(data);
                                       # data={nameAlert: "sensor unreachable : Current_UTC: {} , Sensor_UTC: {}".format(current_rxtime,sensor_rxtime)}
                                       mqtt_client.publish('devices/' + pod_id + '/messages/events/', json.dumps(data), qos=1)
                           else:

                               if name in sensorOffline:
                                   log.debug('sensor came back to online {}'.format(name))
                                   sensorOffline.remove(name)
                       except Exception as e:
                           log.debug("Exception raised in sensor offline publishing state {}".format(e))



                   elif y == "colorHue":
                       colorHue=z
                       rep_status.update({"colorHue": colorHue})
                       rep_status.update(({"color": color}))
                       rep_status_rx.update(({"color": color}))
                   elif y == "colorSat":
                       colorSat=z
                       rep_status.update({"colorSat": colorSat})
                       pass
                   elif y == "colorTemp":

                       colorTemp=z
                       rep_status_rx.update({"colorTemp": colorTemp})
                       rep_status.update({"colrTemp": z})

                   else:
                       rep_status.update({y: z})
                       rep_status_rx.update(({"color": color}))
                       rep_status_rx.update({y: z})


               rep_prop.update({name: rep_status})
               rep_prop_rx.update({name: rep_status_rx})

               if name == "" or str(name).__contains__(" "):
                 pass
               else:
                 devicestatus.update(rep_prop)
                 devicestatuswithoutrx.update(rep_prop_rx)




       # log.info('sensor status  ends')
       return sensor_status_check_only(startIndex+count)
   except Exception as e:
        log.debug("Processing sensor status fails {}".format(e))
        return 1


#Status for sensors which all are connected to IOT gateway was read.
#IOT gateway status api returns identity not name.Name is taken from devicelistbyid dictionary.
#If the sensor has color properties,color is determined by colorHue and colorSat of that
#Reported property for sensors is created like the following format { ":device name" : { ":property key" : ":value" } }
def sensor_status(startIndex):

   global total_devices,iot_ip,colorTemp,podState,intrusionDetection,beforePodState,intrusionDetectionTime,colorSat,colorHue,prePodState
   try:
       if (startIndex >= total_devices):

           return 1
       srid='4'


       response=urllib.request.urlopen(url+iot_ip + '/devices/status?startIndex='+str(startIndex),timeout=URL_TIMEOUT)
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
               # cTime=datetime.datetime.utcnow().replace(microsecond=0)
               # if cTime > intrusionDetectionTime:
               #  diff = cTime - intrusionDetectionTime
               # else:
               #  diff = intrusionDetectionTime - cTime
               # diffSeconds=diff.seconds;
               # # log.debug("name -{} ,cTime - {} ,inTime - {} , diff - {}".format(name,cTime,intrusionDetectionTime,diffSeconds))
               # if intrusionDetection ==1 and ( podState == "Available" or podState == "Reserved" ) and int(diffSeconds) < INTURSION_CHECK_TIMER :
               #     log.debug("intrusion detected,don't trigger color change")
               #     pass
               # elif intrusionDetection ==1 and (podState == "Available in Next 10 min" or podState == "Reserved in Next 10 min") and int(diffSeconds) < INTURSION_CHECK_TIMER:
               #     if beforePodState == "Available" or beforePodState == "Reserved":
               #          log.debug("intrusion detected,don't trigger color change")
               #          pass
               # else:
               #     log.debug("color is - {}".format(color))
               #     if podState == "Available" and color != AVAILCOLOR :
               #         log.debug("trigger color change-available")
               #         group_light_change(AVAILCOLOR)
               #     elif podState == "Reserved" and color != RESERVECOLOR:
               #         log.debug("trigger color change-reserved")
               #         group_light_change(RESERVECOLOR)
               #     elif podState == "Admin In Use" and color != ADMININUSECOLOR:
               #         log.debug("trigger color change-admin in use")
               #         group_light_change(ADMININUSECOLOR)
               #     elif podState =="Reservation In Use" and color != RESERVEINUSECOLOR:
               #         log.debug("trigger color change-reservation in use")
               #         group_light_change(RESERVEINUSECOLOR)
               #     elif podState == "TimeOut" and color != TIMEOUTCOLOR:
               #         log.debug("trigger color change-timeout")
               #         group_light_change(TIMEOUTCOLOR)
               #

           if deviceslistbyid.__contains__(identifier):
               rep_prop = {};
               rep_status = {};
               rep_prop_rx = {}
               rep_status_rx = {};
               name = deviceslistbyid.__getitem__(identifier)[0];
               deviceType = deviceslistbyid.__getitem__(identifier)[1];
               mfg=deviceslistbyid.__getitem__(identifier)[2];
               model = deviceslistbyid.__getitem__(identifier)[2];

               rep_status.update({"deviceType": deviceType})
               rep_status.update({"mfg":mfg});
               rep_status.update({"model":model})
               rep_status_rx.update({"deviceType": deviceType})
               rep_status_rx.update({"deviceType": deviceType})
               rep_status_rx.update({"mfg": mfg});
               rep_status_rx.update({"model": model})

               for y, z in x.items():
                   if y == "rxTime":
                       rep_status.update({y: str(datetime.datetime.utcfromtimestamp(z))})
                       try:
                           current_rxtime=datetime.datetime.utcnow().replace(microsecond=0)
                           sensor_rxtime=datetime.datetime.utcfromtimestamp(z)
                           if current_rxtime > sensor_rxtime:
                               print("crxtime is greater")
                               diff = current_rxtime - sensor_rxtime
                           else:
                               print("sensor rxtime is greater")
                               diff = sensor_rxtime - current_rxtime

                           # log.debug("name - {} ,crxTime -{},srxTime -{},diff.seconds -{}".format(name,current_rxtime,sensor_rxtime,diff.seconds))
                           # log.debug("sensorOffline - {}".format(sensorOffline))
                           if(int(diff.seconds) >= SENSOR_OFFLINE_TIMER):
                               if name in sensorOffline:
                                 pass
                               else:
                                   if name == "" or str(name).__contains__(" "):
                                       pass
                                   else:
                                       log.debug("{} sensor unreachable".format(name))
                                       sensorOffline.append(name)
                                       nameAlert = name+"_alert"
                                       data = {"type": "WARNING", "deviceType": "sensor", "name": nameAlert,
                                               "message": {"status":"sensor unreachable" ,"Current_UTC":str(current_rxtime), "Sensor_UTC":str(sensor_rxtime)}
                                               }
                                       print(data);
                                       # data={nameAlert: "sensor unreachable : Current_UTC: {} , Sensor_UTC: {}".format(current_rxtime,sensor_rxtime)}
                                       mqtt_client.publish('devices/' + pod_id + '/messages/events/', json.dumps(data), qos=1)
                           else:

                               if name in sensorOffline:
                                   log.debug('sensor came back to online {}'.format(name))
                                   sensorOffline.remove(name)
                       except Exception as e:
                           log.debug("Exception raised in sensor offline publishing state {}".format(e))



                   elif y == "colorHue":
                       colorHue=z
                       rep_status.update({"colorHue": colorHue})
                       rep_status.update(({"color": color}))
                       rep_status_rx.update(({"color": color}))
                   elif y == "colorSat":
                       colorSat=z
                       rep_status.update({"colorSat": colorSat})
                       pass
                   elif y == "colorTemp":

                       colorTemp=z
                       rep_status_rx.update({"colorTemp": colorTemp})
                       rep_status.update({"colrTemp": z})

                   else:
                       rep_status.update({y: z})
                       rep_status_rx.update(({"color": color}))
                       rep_status_rx.update({y: z})


               rep_prop.update({name: rep_status})
               rep_prop_rx.update({name: rep_status_rx})

               if name == "" or str(name).__contains__(" "):
                 pass
               else:
                 devicestatus.update(rep_prop)
                 devicestatuswithoutrx.update(rep_prop_rx)

                 mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + srid,
                    str(rep_prop), qos=0)
                 # mqtt_client.publish('devices/' + pod_id + '/messages/events/',json.dumps(rep_prop),qos=1)

       # log.info('sensor status  ends')
       return sensor_status(startIndex+count)
   except Exception as e:
        log.debug("Processing sensor status fails {}".format(e))
        return 1

def sensor_status_publish():
    # log.debug("sensor status publish begins")
    global devicestatuswithoutrx, devicestatustemp,devicestatus
    try:
        jtemp=""
        ltemp=""
        jwithoutBat={}
        lwithoutBat={}
        jwithoutTemp={}
        lwithoutTemp={}

        sensor_status(0)


        if len(devicestatuswithoutrx) == 0:
            for i,j in devicestatus.items():
                data = {"type": "INFO", "deviceType": "sensor", "name":i ,
                    "message": j
                    }
                mqtt_client.publish('devices/' + pod_id + '/messages/events/', json.dumps(data).encode("utf-8"), qos=2)
            # mqtt_client.publish('devices/' + pod_id + '/messages/events/', json.dumps(devicestatus), qos=2)
        for (i, j), (k, l),(m,n) in zip(devicestatuswithoutrx.items(), devicestatustemp.items(),devicestatus.items()):
            if devicestatuswithoutrx.get(i) == devicestatustemp.get(i):
                print("same state")


            else:
                dat = {"type": "INFO", "deviceType": "sensor", "name": m,
                        "message": n
                        }
                # dat = {m: n}
                # log.debug(" j is {}".format(j) )
                # log.debug(" l is {}".format(l))

                if "motion" in j.keys() and "motion" in l.keys():
                    try:
                        log.debug("motion sensor..")
                        jtemp = j.get("temperature")
                        ltemp=l.get("temperature")
                        jwithoutTemp=j.copy()
                        lwithoutTemp=l.copy()
                        jwithoutTemp.pop("temperature")
                        lwithoutTemp.pop("temperature")
                        if "batteryLevel" in j.keys() and "batteryLevel" in l.keys():
                            jbat = j.get("batteryLevel")
                            lbat = l.get("batteryLevel")
                            jwithoutBat=jwithoutTemp.copy()
                            lwithoutBat=lwithoutTemp.copy()
                            jwithoutBat.pop("batteryLevel")
                            lwithoutBat.pop("batteryLevel")
                            log.debug("j ::: {} ".format(jwithoutBat))
                            log.debug("l ::: {} ".format(lwithoutBat))
                            if int(jbat) > int(lbat):
                                diffbat=int(jbat)-int(lbat)
                            else:
                                diffbat=int(lbat)-int(jbat)
                            # log.debug("jbat {} ,lbat {} ,diffbat {}".format(jbat,lbat,diffbat))
                            if diffbat > 5:
                                log.debug("battery level differnece grater than 5")

                                mqtt_client.publish('devices/' + pod_id + '/messages/events/', json.dumps(dat).encode("utf-8"), qos=1)

                        if int(jtemp.split('.')[0]) > int(ltemp.split('.')[0]):
                            difftemp=int(jtemp.split('.')[0]) - int(ltemp.split('.')[0])
                        else:
                            difftemp = int(ltemp.split('.')[0]) - int(jtemp.split('.')[0])

                        if difftemp <= 1:
                            pass
                        else:
                            mqtt_client.publish('devices/' + pod_id + '/messages/events/', json.dumps(dat).encode("utf-8"), qos=1)

                        if jwithoutBat == lwithoutBat:
                            log.debug("rest also same")
                        else:
                            mqtt_client.publish('devices/' + pod_id + '/messages/events/', json.dumps(dat).encode("utf-8"), qos=1)
                    except Exception as e:
                        log.debug("Exception raised in sensor_status_publish motion sensor - {}".format(e))

                else:
                    log.debug("different state")
                    print("i is {} , j is {}".format(i,j))
                    log.debug("i is {} , j is {}".format(i,j))
                    log.debug("k is {} ,l is {}".format(k,l))
                    log.debug("m is {} , n is {}".format(m,n))
                    # dat={i:j}
                    mqtt_client.publish('devices/' + pod_id + '/messages/events/?rid=2300', json.dumps(dat).encode("utf-8"), qos=1)

                    print("\t\t\t\tdevice status{}".format(devicestatus))


        devicestatustemp = devicestatuswithoutrx.copy()

        #log.debug("after a is {} ,\n\t b is {}".format(devicestatustemp, devicestatuswithoutrx))
    except Exception as e:
        log.debug("Exception - sensor status publish -{}".format(e))

    log.debug("sensor status publish ends")

#Number of bytes transfered and received through the cradle point's lan and wan network is send to cloud as telementery data

def network_stats():
    global conn_type
    try:
        conn_type=cs.CSClient().get("/status/wan/primary_device").get("data")
        mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + grid,
                            "{\"conn_type\":\"" + conn_type + "\"}", qos=0)

        wan_in=cs.CSClient().get("/status/stats/usage/wan_in").get("data");
        wan_out=cs.CSClient().get("/status/stats/usage/wan_out").get("data");
        lan_in=cs.CSClient().get("/status/stats/usage/lan_in").get("data");
        lan_out=cs.CSClient().get("/status/stats/usage/lan_out").get("data");
        for (wi,wo,li,lo) in zip(wan_in,wan_out,lan_in,lan_out):
            s={"wan_in":  str(wi),"wan_out" :str(wo),"lan_in" :str(li), "lan_out" : str(lo) }
            data = {"type": "INFO", "deviceType": "cradlepoint", "name": "network status",
                    "message":s
                    }
            # mqtt_client.publish('devices/' + pod_id + '/messages/events/', "{\"wan_in\":" + str(wi) + " , \"wan_out\" :"+str(wo)+" ,\"lan_in\" :"+str(li)+ ", \"lan_out\" : "+str(lo)+ " }",
            #                 qos=0)
            mqtt_client.publish('devices/' + pod_id + '/messages/events/',
                                json.dumps(data),
                                qos=0)
    except Exception as e:
        log.debug("Exception - network stats {}".format(e))

#Total devices connected to IOT gateway
def get_number_of_devices():
    global total_devices,tdflag,tdevent,offlineDevices
    global iot_ip
    try:

        res=urllib.request.urlopen(url+iot_ip + '/devices',timeout=URL_TIMEOUT)
        nres=res.read()
        number_of_devices= json.loads(nres)
        total_devices=number_of_devices.get("devices").get("totalDevices")
        if total_devices == 0:
            tdflag = tdflag+1
        else:
            tdflag = 0
            if "totalDevices" in offlineDevices:
                log.debug("total devices count greater than 0 ")
                offlineDevices.remove("totalDevices")
        if tdflag > tdevent:
            print("publish")
            if "totalDevices" in offlineDevices:
                pass
            else:
                offlineDevices.append("totalDevices")
                data = {"type": "CRITICAL", "deviceType": "sensor", "name": "All sensors",
                        "message": {"status":"sensors are not commisioned"}
                        }
                # mqtt_client.publish('devices/' + pod_id + '/messages/events/',
                #                 "{\"SENSORS_ALERT\": \"sensors are not commisioned\" }",
                #                 qos=1)
                mqtt_client.publish('devices/' + pod_id + '/messages/events/',
                                    json.dumps(data),
                                    qos=1)


        return total_devices;
    except Exception as e:

        log.debug("retreiving number of devices fails {}".format(e))
        return 0


#Devices name,type and identifier which all are connected to IOT gateway is stored in dictionary for further references
def device_list(startIndex):
    global total_devices,iot_ip
    try:
        total_devices = get_number_of_devices()
    except Exception as e:
        log.debug("Exception raises in total_devices {}".format(e))
        total_devices=0


    try:
            if (startIndex >= total_devices):
                return 1

            response=urllib.request.urlopen(url+iot_ip + '/devices/info?startIndex='+str(startIndex),timeout=URL_TIMEOUT)
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
                print( " device list is {}".format(devicelist))
                count=count+1;
            return device_list(startIndex+count)

    except Exception as e:
            log.debug("Retrieving device list fails -{}".format(e))
            return 1

def devices_list_update():
    global deviceslistbyid
    try:
        log.debug("deviceList -- {}".format(deviceslistbyid.keys()))
        deviceslistbyid={}
        log.debug("deviceList -- {}".format(deviceslistbyid.keys()))
        device_list(0)
    except Exception as e:
        log.debug("Excception in devices list update - {}".format(e));

def mqtt_connect():
    global mqtt_flag
    log.debug("mqtt connect called")
    try:

        mqtt_client.connect(iot_hub_name + '.azure-devices.net', 8883)
        mqtt_flag=1
    except Exception as e:
        log.debug("mqtt exception raises {}".format(e))
        mqtt_flag=0
    mqtt_client.loop_forever()
#If device name is renamed on IOTgateway,the old name reported properties is deleted from the cloud

def device_list_manage():
    try:
        log.debug("old deviceslist - {}".format(old_devicelistbyid.keys()))
        log.debug("deviceslist - {}".format(deviceslistbyid.keys()))
        if deviceslistbyid.__len__() != 0:
            print("devicelist dict is non empty")
            for i in old_devicelistbyid.keys():
                if (i in deviceslistbyid.keys()):
                    if old_devicelistbyid.get(i)[0] != deviceslistbyid.get(i)[0]:
                        mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + grid,
                                              "{\""+old_devicelistbyid.get(i)[0]+"\":null}", qos=1)

                if i not in deviceslistbyid.keys():
                    print("if not in {}, {}".format(i,old_devicelistbyid.get(i)[0]))
                    if old_devicelistbyid.get(i)[0] != None:
                        mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + grid,
                                        "{\"" + old_devicelistbyid.get(i)[0] + "\":null}", qos=1)


        old_devicelistbyid.update(deviceslistbyid.copy())

    except Exception as e:
        log.debug("Exception - device list manage - {}".format(e))
    group()
def offline_online_check():
    global offline
    try:
        conn_state = cs.CSClient().get("/status/wan/connection_state").get("data")
        if conn_state.lower() == "connected":
            if offline == 1:
                log.debug("came back to online")
                # get_desired()
                offline=0
        else:
            log.debug("device is offline")
            offline = 1
    except Exception as e:
        log.debug("Exception - offline online check {} ".format(e))


# def health_monitoring():
#     global unreachable_host,healthFlag
#     if healthFlag == 1:
#         pass
#     else:
#         healthFlag = 1
#         iotHost=internalHost=unlockHost="0.0.0.0"
#         log.debug("unreachable hosts = {}".format(unreachable_host))
#         try:
#             mac_list = cs.CSClient().get('/config/dhcpd/reserve').get('data')
#
#             if (mac_list != None):
#                 if (len(mac_list) > 0):
#                     if "all" in unreachable_host:
#                         unreachable_host.remove("all")
#                     for item in mac_list:
#                         host = item["ip_address"]
#                         hostname=item["hostname"]
#                         if hostname.upper().__contains__("UNLOCK"):
#                             unlockHost = host
#                         if hostname.upper().__contains__("GATEWAY"):
#                             iotHost = host
#                         if hostname.upper().__contains__("WIN"):
#                             internalHost=host
#                         cstore = cs.CSClient()
#                         cstore.put('control/ping/start/host', host)
#                         cstore.put('control/ping/start/size', 64)
#
#                         print('ping host: %s', host)
#                         result = {}
#                         try_count = 0;
#
#                         while try_count < 3:
#                             result = cstore.get('control/ping')
#                             if result.get('data') and result.get('data').get('status') in ["error", "done"]:
#                                 break
#                             time.sleep(5)
#                             try_count += 1
#
#                         error_str = ""
#                         if try_count == 3 or not result.get('data') or result.get('data').get('status') != "done":
#                             error_str = "An error occurred"
#                             if host in unreachable_host:
#                               pass
#                             else:
#                                 unreachable_host.append(host)
#                                 if hostname.__contains__("GATEWAY"):
#                                     data = {"type": "WARNING", "deviceType": "IOTgateway", "name": hostname,
#                                         "message": {"status":"Ping request failed ","host":host,"reason":result['data']['result']}}
#                                 else:
#                                     data = {"type": "WARNING", "deviceType": "Zenspace devices", "name": hostname,
#                                             "message": {"status":"Ping request failed" ,"host":host,"reason":result['data']['result']}
#                                             }
#
#
#                                 # mqtt_client.publish('devices/' + pod_id + '/messages/events/',
#                                 #                     "{\"health_monitor\": \""+host + " - "+ hostname+" ping request failed \" }",
#                                 #                     qos=1)
#                                 mqtt_client.publish('devices/' + pod_id + '/messages/events/',
#                                                     json.dumps(data),
#                                                     qos=1)
#                         if result.get('data').get('status') == "done":
#                             if host in unreachable_host:
#                                 unreachable_host.remove(host)
#
#                         log.debug("ping result:  FOR host %s  %s\n%s", host, error_str, result['data']['result'])
#             else:
#                 if "all" in unreachable_host:
#                     pass
#                 else:
#                     unreachable_host.append("all")
#                     data = {"type": "CRITICAL", "deviceType": "Zenspace devices", "name":"All devices" ,
#                             "message": {"status":"No device found"}
#                             }
#                     # mqtt_client.publish('devices/' + pod_id + '/messages/events/',
#                     #                     "{\"health_monitor\": \"MAC address is not found\" }",
#                     #                     qos=1)
#                     mqtt_client.publish('devices/' + pod_id + '/messages/events/',
#                                         json.dumps(data),
#                                         qos=1)
#
#                 # log.info("ping result: %s\n%s", error_str)
#             app_healthcheck(iotHost,unlockHost,internalHost)
#             log.debug(" UnReachable host - {}".format(unreachable_host))
#             healthFlag=0
#         except Exception as e:
#             log.debug("Exception raised in health monitoring = {}".format(e))
#             healthFlag=0


def health_monitoring():
    global unreachable_host,healthFlag
    if healthFlag == 1:
        pass
    else:
        healthFlag = 1
        iotHost=internalHost=unlockHost="0.0.0.0"
        print("unreachable hosts = {}".format(unreachable_host))
        try:
            mac_list = cs.CSClient().get('/config/dhcpd/reserve').get('data')

            if (mac_list != None):
                if (len(mac_list) > 0):
                    if "all" in unreachable_host:
                        unreachable_host.remove("all")
                    for item in mac_list:
                        host = item["ip_address"]
                        hostname=item["hostname"]
                        if hostname.upper().__contains__("UNLOCK"):
                            unlockHost = host
                        if hostname.upper().__contains__("GATEWAY"):
                            iotHost = host
                        if hostname.upper().__contains__("WIN"):
                            internalHost=host
                        cstore = cs.CSClient()



                        print('ping host: %s', host)
                        result = {}
                        try_count = 0;


                        while try_count < 3:
                            r=cstore.put('control/ping/start/host', host)
                            print("response is {}".format(r))
                            time.sleep(5)
                            result = cstore.get('control/ping')
                            print("result is {}".format(result.get('data').get('status')))

                            if result.get('data') and result.get('data').get('status') in ["running"]:
                                time.sleep(4)
                                result = cstore.get('control/ping')


                            print("\n\n\t\t {}".format(result.get('data').get('status')))
                            if result.get('data') and result.get('data').get('status') in ["done"]:
                                    break

                            try_count += 1

                        error_str = ""
                        if try_count == 3 and result.get('data').get('status') == "error":
                            error_str = "An error occurred"
                            if host in unreachable_host:
                              pass
                            else:
                                unreachable_host.append(host)
                           #     print("\n\nresult is"+ host+"--"+result['data']['result'])
                                if hostname.__contains__("GATEWAY"):
                                    print("hello")
                                    data = {"type": "WARNING", "deviceType": "IOTgateway", "name": hostname,
                                        "message": {"status":"Ping request failed ","host":host,"reason":result['data']['result']}}
                                else:
                                    data = {"type": "WARNING", "deviceType": "Zenspace devices", "name": hostname,
                                            "message": {"status":"Ping request failed" ,"host":host,"reason":result['data']['result']}
                                            }
                                mqtt_client.publish('devices/' + pod_id + '/messages/events/',
                                                                                    json.dumps(data),
                                                                                    qos=1)


                        if result.get('data').get('status') == "done":
                            if host in unreachable_host:
                                unreachable_host.remove(host)

                        print("ping result:  FOR host {}  {}\n{}".format( host, error_str, result['data']['result']))
                        time.sleep(4)
            else:
                if "all" in unreachable_host:


                    pass
                else:
                    unreachable_host.append("all")
                    data = {"type": "CRITICAL", "deviceType": "Zenspace devices", "name":"All devices" ,
                            "message": {"status":"No device found"}
                            }
                    mqtt_client.publish('devices/' + pod_id + '/messages/events/',json.dumps(data),qos=1)


            app_healthcheck(iotHost, unlockHost, internalHost)
            print(" UnReachable host - {}".format(unreachable_host))
            healthFlag=0
        except Exception as e:
            print("Exception raised in health monitoring = {}".format(e))
            healthFlag=0



def app_healthcheck(iotHost,unlockHost,internalHost):
    global unlockKeepAlive,unlockKeepAliveTimer,unreachable_host,podState,zenspaceKeepAlive,zenspaceKeepAliveTimer,cameraKeepAlive,cameraKeepAliveTimer
    global zenspaceState,teamViewerState,airServerState
    conn_type=""
    try:
        conn_type = cs.CSClient().get("/status/wan/primary_device").get("data")
    except Exception as e:
        log.debug("Exception raised in conn_type {}".format(e))
    sensorList=[]





    try:
        currenttime=datetime.datetime.utcnow().replace(microsecond=0)
        if unlockKeepAlive > currenttime:
            unlockdiff = unlockKeepAlive -currenttime
        else:
            unlockdiff = currenttime - unlockKeepAlive

        if zenspaceKeepAlive > currenttime:
            zenspacediff = zenspaceKeepAlive - currenttime
        else:
            zenspacediff = currenttime - zenspaceKeepAlive

        if cameraKeepAlive > currenttime:
            cameradiff = cameraKeepAlive - currenttime
        else:
            cameradiff = currenttime - cameraKeepAlive

        # '''
        #          Ping Status      App Keepalive      App status
        #           YES                > time diff       UNLOCK
        #           NO                 > time diff        UNREACHABLE
        #           NO                  < TIME DIFF       PING
        #          YES                < time diff       REACHABLE
        #     '''


        if unlockHost == "0.0.0.0":
            externalState = "NOT RESERVED"
        else:
            if int(unlockdiff.seconds) > unlockKeepAliveTimer and unlockHost in unreachable_host:
                externalState = "UNREACHABLE"
            elif int(unlockdiff.seconds) > unlockKeepAliveTimer:
                    print("unlock app state is UNLOCK")
                    externalState = "UNLOCK"
            elif unlockHost in unreachable_host:
                externalState = "PING"
            else:
                externalState = "REACHABLE"

        '''
         Ping Status      App Keep Alive  camera App keep alive    App Status
             YES            > time diff     > time diff              ZenCam ( Both Apps)
             YES            > time diff      < time diff             ZenSpace
             YES            < time diff       >time diff             CAMERA
             YES            < time diff       <time diff             REACHABLE
             NO             > time diff       > time diff             UNREACHABLE
             NO             > time diff       < time diff             PINGZEN
             NO             < time diff       > time diff             PINGC
             NO             <time diff        < time diff             PING
             YES             UNINSTALLED      >time diff              ZENUNCAM
             YES             UNINSTALLED      <time diff              ZENSPACEUN
             NO              UNINSTALLED      >time diff              PINGCAMZENUN
             NO              UNINSTALLED      <time diff              PINGZENUN
        '''

        if int(zenspacediff.seconds) > zenspaceKeepAliveTimer:
            zenstate = "yes"
        else:
            zenstate = "no"
        if int(cameradiff.seconds) > cameraKeepAliveTimer:
            camstate = "yes"
        else:
            camstate = "no"

        if internalHost == "0.0.0.0":
            internalState = "NOT RESERVED"
        elif zenspaceState.lower() == "false":
            if internalHost in unreachable_host:
                if camstate == "yes":
                    internalState = "PINGCAMZENUN"
                else:
                    internalState="PINGZENUN"
            else:
                if camstate == "yes":
                    internalState = "ZENUNCAM"
                else:
                    internalState = "ZENSPACEUN"

        else:
            if internalHost in unreachable_host:
                if zenstate == "yes":
                    if camstate == "yes":
                        internalState="UNREACHABLE"
                    else:
                        internalState = "PINGZEN"
                else:
                    if camstate == "yes":
                        internalState="PINGC"
                    else:
                        internalState="PING"
            else:
                if zenstate == "yes":
                    if camstate == "yes":
                        internalState="ZENCAM"
                    else:
                        internalState = "ZENSPACE"
                else:
                    if camstate == "yes":
                        internalState="CAMERA"
                    else:
                        internalState="REACHABLE"



        #'''
        #   PING    SERVER
        #   YES      ok         REACHABLE
        #   YES      notok      IOTSERVER
        #   NO       ok         PING
        #   NO       notok      UNREACHABLE
        #'''
        if iotHost == "0.0.0.0":
            iotGatewayState = "NOT RESERVED"
        else:

            try:
                res = urllib.request.urlopen(url + iot_ip + '/gateway', timeout=URL_TIMEOUT)
                if res.status == 200:
                    iotserver="ok"
                else:
                    iotserver = "notok"
            except Exception as e:
                log.debug(e)
                iotserver = "notok"

            if iotHost in unreachable_host:
                if iotserver == "ok":
                    iotGatewayState = "PING"
                else:
                    iotGatewayState = "UNREACHABLE"
            else:
                if iotserver == "ok":
                    iotGatewayState = "REACHABLE"
                else:
                    iotGatewayState = "IOTSERVER"


        if teamViewerState.lower() == "true":
            tstate="INSTALLED"
        else:
            tstate = "NOT INSTALLED"

        if airServerState.lower() == "true":
            astate = "INSTALLED"
        else:
            astate = "NOT INSTALLED"

        sensor=sensor_check()

        data={"type":"INFO","deviceType":"MONITOR","name":"monitor","message":{"podstate": podState,"connType":conn_type,"iotGateway":iotGatewayState,"external":externalState,"internal":internalState,"teamviewer":tstate,"airserver":astate,"sensors":sensor}}
        mqtt_client.publish('devices/' + pod_id + '/messages/events/',json.dumps(data),qos=1)
    except Exception as e:
        log.debug("Exception raises in app_helathcheck - {}".format(e))

def sensor_check():
    global sensorOffline
    sensors=[];

    ##door##
    if "door_lock" in sensorOffline:
        availableDoor=0
    else:
        availableDoor=1

    doorSensor={"name":"door_lock","available":availableDoor,"total":1}
    sensors.append(doorSensor)

    ##light##
    try:
        res = urllib.request.urlopen(url + iot_ip + '/groups/id/' + str(group_id), timeout=URL_TIMEOUT)
        group = json.loads(res.read())
        print(group)
        if "group" in group.keys():
            gr = group.get("group")
            if gr != None:
                members = gr.get("list")
                print(members)
                off = 0
                total = len(members)
                for i in members:
                    print(i)
                    try:
                        res = urllib.request.urlopen(url + iot_ip + '/devices/status/' + i, timeout=URL_TIMEOUT)
                        memstate = json.loads(res.read())
                        if "deviceStatus" in memstate:
                            state = memstate.get("deviceStatus").get("list")
                            if state != None:
                                for s in state:
                                    rxtime = s.get("rxTime")
                                    sensorTime = datetime.datetime.utcfromtimestamp(rxtime)
                                    currentTime = datetime.datetime.utcnow().replace(microsecond=0)
                                    print(" sensor time {} , currenttime {}".format(sensorTime, currentTime))
                                    if sensorTime > currentTime:
                                        diff = sensorTime - currentTime
                                    else:
                                        diff = currentTime - sensorTime

                                    if int(diff.seconds) > SENSOR_OFFLINE_TIMER:
                                        off = off + 1
                    except Exception as e:
                        log.debug("Exception raised in light state check = {}".format(e))
        # print("offline count = {} , total - {}".format(off, total))
        onLight=total-off
        lightSensor={"name":"lights","available": onLight , "total": total}
        sensors.append(lightSensor)
    except Exception as e:
        log.debug("Exeption raised in light helath check - {}".format(e))
    return sensors


def lock_door():
    try:
        log.debug("locking the door...")
        if devicelist.__contains__("door_lock"):
            id = devicelist.__getitem__("door_lock")[0]
            response = urllib.request.urlopen(url + iot_ip + '/devices/status/' + id,timeout=URL_TIMEOUT)
            dres = response.read()
            res = json.loads(dres);
            dstatus = res.get("deviceStatus")

            list = res.get("deviceStatus").get("list")
            currenttime = datetime.datetime.utcnow().replace(microsecond=0)
            for l in list:
                dat = {"on": "true"}
                # log.debug("data is {}".format(data))
                data = json.dumps(dat).encode('utf-8')
                req = urllib.request.Request(url + iot_ip + '/devices/' + id, headers=headers,
                                             data=data,
                                             method="PUT")
                resp = urllib.request.urlopen(req, timeout=URL_TIMEOUT)
                log.debug("door locked")
                # sensor_status(0)
                sensor_status_publish()

                lctimestamp = l.get("rxTime")
                lctime = datetime.datetime.utcfromtimestamp(lctimestamp)
                if currenttime > lctime:

                    diff = currenttime - lctime
                else:

                    diff = lctime - currenttime

                diffsec = diff.seconds
                if (diffsec < SENSOR_OFFLINE_TIMER):
                  pass
                else:
                    log.debug("door lock is unreachable")
                    if "door_lock" in sensorOffline:
                        pass
                    else:
                        sensorOffline.append("door_lock")
                        data = {"type": "WARNING", "deviceType": "sensor", "name": "door_lock",
                                "message": {"status":"sensor unreachable","Current_UTC":str(currenttime),"Sensor_UTC":str(lctime)}
                                }
                        # mqtt_client.publish('devices/' + pod_id + '/messages/events/',
                        #                 "{\"door_lock_alert\": \"sensor unreachable : Current_UTC: {} ,Sensor_UTC: {}\" }".format(currenttime,lctime),
                        #                 qos=1)
                        mqtt_client.publish('devices/' + pod_id + '/messages/events/',
                                            json.dumps(data),
                                            qos=1)

        else:
            log.debug("door lock id is missing")
            if "door_lock" in sensorOffline:
                pass
            else:
                sensorOffline.append("door_lock")
                data = {"type": "CRITICAL", "deviceType": "sensor", "name": "door_lock",
                    "message": {"status":"Either IOTgateway is not reachable / door_lock is not commisioned"}
                    }

                mqtt_client.publish('devices/' + pod_id + '/messages/events/',
                                json.dumps(data),
                                qos=1)

            # mqtt_client.publish('devices/' + pod_id + '/messages/events/',
            #                     "{\"door_lock_alert\": \"sensor missing \" }",
            #                     qos=1)
    except Exception as e:
        log.debug("Exception - locking the door -- {}".format(e))

def unlock_door():
    try:
        log.debug("unlocking the door...")
        if devicelist.__contains__("door_lock"):
            id = devicelist.__getitem__("door_lock")[0]
            response = urllib.request.urlopen(url + iot_ip + '/devices/status/' + id,timeout=URL_TIMEOUT)
            dres = response.read()
            res = json.loads(dres);
            dstatus = res.get("deviceStatus")

            list = res.get("deviceStatus").get("list")
            currenttime = datetime.datetime.utcnow().replace(microsecond=0)
            for l in list:
                dat = {"on": "false"}
                # log.debug("data is {}".format(data))
                data = json.dumps(dat).encode('utf-8')
                req = urllib.request.Request(url + iot_ip + '/devices/' + id, headers=headers,
                                             data=data,
                                             method="PUT")
                resp = urllib.request.urlopen(req, timeout=URL_TIMEOUT)
                log.debug("door locked")
                # sensor_status(0)
                sensor_status_publish()

                lctimestamp = l.get("rxTime")
                lctime = datetime.datetime.utcfromtimestamp(lctimestamp)
                if currenttime > lctime:

                    diff = currenttime - lctime
                else:

                    diff = lctime - currenttime

                diffsec = diff.seconds
                if (diffsec < SENSOR_OFFLINE_TIMER):
                  pass
                else:
                    log.debug("door lock is unreachable")
                    if "door_lock" in sensorOffline:
                        pass
                    else:
                        sensorOffline.append("door_lock")
                        data = {"type": "WARNING", "deviceType": "sensor", "name": "door_lock",
                                "message": {"status":"sensor unreachable","Current_UTC":str(currenttime),"Sensor_UTC": str(lctime)}
                                }
                        # mqtt_client.publish('devices/' + pod_id + '/messages/events/',
                        #                 "{\"door_lock_alert\": \"sensor unreachable : Current_UTC: {} ,Sensor_UTC: {}\" }".format(currenttime,lctime),
                        #                 qos=1)
                        mqtt_client.publish('devices/' + pod_id + '/messages/events/',
                                            json.dumps(data),
                                            qos=1)

        else:
            log.debug("door lock id is missing")
            if "door_lock" in sensorOffline:
                pass
            else:
                sensorOffline.append("door_lock")
                data = {"type": "CRITICAL", "deviceType": "sensor", "name": "door_lock",
                        "message": {"status":"Either IOTgateway is not reachable / door_lock is not commisioned"}
                        }

                mqtt_client.publish('devices/' + pod_id + '/messages/events/',
                                    json.dumps(data),
                                    qos=1)

            # mqtt_client.publish('devices/' + pod_id + '/messages/events/',
            #                     "{\"door_lock_alert\": \"sensor missing \" }",
            #                     qos=1)
    except Exception as e:
        log.debug("Exception - locking the door -- {}".format(e))


#IPadServer
def start_server():
    server_address = ('', 9001)

    print('Starting Server: {}'.format(server_address))
    log.info('IPadServer started');

    # httpd.socket = ssl.wrap_socket(httpd.socket, certfile='./server.pem',server_side=True)

    try:
        httpd = HTTPServer(server_address, SimpleHTTPRequestHandler)
        log.debug("client address {} -- {}".format(httpd.server_name,httpd.server_address))
        httpd.serve_forever()


    except Exception as e:
        print('Stopping Server, Key Board interrupt')
        log.debug("Exception in startig server 9001 {}".format(e))
        data = {"type": "CRITICAL", "deviceType": "cradlepoint", "name": "9001 server",
                "message": {"status": "Server is not running {}".format(e)}
                }

        mqtt_client.publish('devices/' + pod_id + '/messages/events/',
                            json.dumps(data),
                            qos=1)

    return 0

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    global podState,iot_ip,state,beforePodState,devicestatus,colorTemp,colorSat,colorHue,intruderState,prePodState

    def do_GET(self):
        global lightState, lightColor, colorTemp, doorState, lockState,lightLevel,intruderState,state,unlockKeepAlive,zenspaceKeepAlive
        if None != re.search('/sensor/status',self.path):
            try:


                # sensor_status(0)
                sensor_status_check_only(0)
                self.send_response(200)
                self.send_header('Content-Type','application/json')
                self.end_headers()
                s=json.dumps(devicestatus).encode('utf-8')

                self.wfile.write(s)
            except Exception as e:
                log.debug("Exception occurs in get /sensor/info --{}".format(e))
                self.send_response(503)
                self.end_headers()
        elif None != re.search('/pod/id',self.path):
            log.debug("/pod/id - {}".format(pod_id))
            data={"podId":pod_id}
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            s = json.dumps(data).encode('utf-8')
            self.wfile.write(s)

        elif None != re.search('/pod/state',self.path):

            log.debug("pod state is {}".format(podState))
            podstate={"state":podState,"intruder_state":intruderState}
            self.send_response(200)
            self.send_header('Content-Type','application/json')
            self.end_headers()
            podstateData=json.dumps(podstate).encode('utf-8')
            self.wfile.write(podstateData)
        # Keepalive api endpoint for Unlock ipad
        elif None != re.search('/keepalive',self.path):
            try:


                # sensor_status(0)
                unlockKeepAlive= datetime.datetime.utcnow().replace(microsecond=0)
                log.debug(" Keep alive timestamp -{}".format(unlockKeepAlive))
                self.send_response(200)
                self.send_header('Content-Type','application/json')
                self.end_headers()
                self.wfile.write(b'Success')
            except Exception as e:
                log.debug("Exception occurs in get /keepalive --{}".format(e))
                self.send_response(503)
                self.end_headers()



        elif None != re.search('/pod/LightDoorstate',self.path):
              zenspaceKeepAlive=datetime.datetime.utcnow().replace(microsecond=0)
              # sensor_status(0)
              try:
                  sensor_status_check_only(0)
                  print("device status is {}".format(devicestatus))
                  for i, j in devicestatus.items():
                      print("i is {} , j is {}".format(i, j))
                      if i == "door_lock":
                          print("door state is {}".format(j.get("on")))
                          doorState=j.get("on")
                      if j.get("deviceType") == "light" and "color" in j.keys():
                          print("light state is {} and light color is {} ".format(j.get("on"), j.get("color")))
                          if j.get("on") == "" or str(j.get("on")).__contains__(" "):
                              pass
                          else:
                            lightState=j.get("on")
                          if j.get("color") == "" or str(j.get("color")).__contains__(" "):
                              pass
                          else:
                            lightColor=j.get("color")
                          if j.get("level") == "" or str(j.get("level")).__contains__(" "):
                              pass
                          else:
                            lightLevel=j.get("level")
                  ldState={"light_state":lightState,"light_color":lightColor,"light_level":lightLevel,"door_state":doorState,"light_temp":colorTemp,"lock_status":lockstate,"light_status":state}
                  self.send_response(200)
                  self.send_header('Content-Type', 'application/json')
                  self.end_headers()
                  ldStateData = json.dumps(ldState).encode('utf-8')
                  self.wfile.write(ldStateData)
              except Exception as e:
                  log.debug("Exception - pod/LightDoorstate - {}".format(e))
                  self.send_response(200)
                  self.send_header('Content-Type', 'application/json')
                  self.end_headers()




        elif None != re.search('/podLightstate', self.path):
            try:
                log.debug("pod state is {}   light state is {}".format(podState,state))
                # podstate = {"podState": podState , "lightState":state ,"prevpodState":beforePodState}
                podstate = {"podState": podState, "lightState": state, "prevpodState": prePodState}
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                podstateData = json.dumps(podstate).encode('utf-8')
                self.wfile.write(podstateData)
            except Exception as e:
                log.debug("Exception - /pod/Lightstate -- {}".format(e))
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
        else:
            self.send_response(404)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'Invalid URL')





    def do_PUT(self):
        global teamViewerState,zenspaceState,cameraKeepAlive,airServerState
        log.debug("PUT request")
        erid="2000"
        if None != re.search('/eventhub', self.path):
            if 'Content-Type' in self.headers:
                type = self.headers['Content-Type']
                if type == "application/json":
                    try:
                        content_length = int(self.headers['Content-Length'])

                        body = self.rfile.read(content_length)
                        data=json.loads(body)
                        mqtt_client.publish('devices/' + pod_id + '/messages/events/', json.dumps(data), qos=1)

                        self.send_response(200)
                        self.end_headers()
                        self.wfile.write(b'Success')
                    except Exception as e:
                        res = "412,bad request-{}".format(e)
                        log.debug("Exception raised in /eventhub post request {}".format(e))
                        self.send_response(412)
                        self.end_headers()
                        self.wfile.write(b'BAD Request')
                else:
                        res="415,bad request"
                        self.send_response(415)
                        self.end_headers()
                        self.wfile.write(b'BAD Request')
                        log.debug(" 415 bad request")
            else:
                        res="412 ,Bad request"
                        self.send_response(412)
                        self.end_headers()
                        self.wfile.write(b'BAD Request')
                        log.debug(" 412 bad request")

        elif None != re.search('/camerakeepalive',self.path):
            if 'Content-Type' in self.headers:
                type = self.headers['Content-Type']
                if type == "application/json":
                    try:
                        cameraKeepAlive = datetime.datetime.utcnow().replace(microsecond=0)
                        log.debug(" Keep alive timestamp -{}".format(cameraKeepAlive))
                        content_length = int(self.headers['Content-Length'])

                        body = self.rfile.read(content_length)
                        data = json.loads(body)
                        log.debug(body)
                        if "teamviewer" in data.keys():
                            teamViewerState = data.get("teamviewer")
                        if "zenspace" in data.keys():
                            zenspaceState=data.get("zenspace")
                        if "airserver" in data.keys():
                            airServerState=data.get("airserver")


                        self.send_response(200)
                        self.end_headers()
                        self.wfile.write(b'Success')
                    except Exception as e:
                        res = "412,bad request-{}".format(e)
                        log.debug("Exception raised in /eventhub post request {}".format(e))
                        self.send_response(412)
                        self.end_headers()
                        self.wfile.write(b'BAD Request')
                else:
                    res = "415,bad request"
                    self.send_response(415)
                    self.end_headers()
                    self.wfile.write(b'BAD Request')
                    log.debug(" 415 bad request")
            else:
                res = "412 ,Bad request"
                self.send_response(412)
                self.end_headers()
                self.wfile.write(b'BAD Request')
                log.debug(" 412 bad request")



        else:
            log.debug("Invalid url");
            self.send_response(404);
            self.end_headers()



    def do_POST(self):
        log.debug("POST request")
        global podState, prevPodState,group_id,state,beforePodState,intrusionDetection,intrusionDetectionTime,intrusion,lockstate,doorLockException,intruderState,reservePodState
        global prePodState
        if None != re.search('/doorLock', self.path):
                global podState
                log.debug("/doorLock state of the pod is  {}".format(podState))
                # if podState == "Admin In Use":
                #     self.send_response(503)
                #     self.end_headers()
                #     self.wfile.write(b'Admin In Use')
                # else:
                res=''
                pin=''
                if 'Content-Type' in self.headers:
                    type = self.headers['Content-Type']
                    if type == "application/json":
                        try:
                            content_length = int(self.headers['Content-Length'])



                            body = self.rfile.read(content_length)
                            log.debug("request body - {}".format(body))

                            data = json.loads(body)
                            # conn_state = cs.CSClient().get("/status/wan/connection_state").get("data")
                            # if conn_state.lower() == "connected":
                            for x, y in data.items():

                                if x == "pin":
                                   pin =y
                                   reservePodState=podState
                                   s = verifyAuth(y)

                                   log.debug(" Value returned from authverify{}".format(s))

                                   if s == 0:
                                       res="200,Door Opened"
                                       log.debug("Reservation user logging in ,state is--{}".format(podState))


                                       log.debug("Admin is not there")
                                       self.send_response(200)
                                       self.end_headers()
                                       self.wfile.write(b'Door Opened')
                                       log.debug("response code is {} - response text is {}".format("200","Door Opened"))

                                       if reservePodState == "Reservation In Use":
                                           log.debug("Reservation user loging in when state is {}".format(podState))
                                           pass
                                       else :
                                           update_pod_state()

                                           # sensor_status(0)
                                           sensor_status_publish()
                                           inform_pod_state()


                                   elif s == 1:
                                       res="1,UnAuthorized"
                                       self.send_response(401)
                                       self.end_headers()
                                       self.wfile.write(b'UnAuthorized')
                                       log.debug(" UnAuthorised")
                                   elif s == 2:
                                       res="500,Failed to reach gateway"
                                       self.send_response(500)
                                       self.end_headers()
                                       self.wfile.write(b'Fail to reach gateway')
                                       log.debug(" Failed to reach gateway")
                                   elif s == 20:
                                       res="412,No door_lock sensor"
                                       self.send_response(412)
                                       self.end_headers()
                                       self.wfile.write(b'No door_lock sensor')
                                       log.debug(" No door sensor")
                                   elif s == 202:
                                       res="202,Accepted"
                                       self.send_response(202)
                                       self.end_headers()
                                       self.wfile.write(b'Accepted')
                                       log.debug("response code is {} - response text is {}".format("202", "Accepted"))
                                   elif s == 212:
                                       res="212,Admin in use"
                                       self.send_response(503)
                                       self.end_headers()
                                       self.wfile.write(b'Admin In Use')
                                       log.debug(" Admin in Use")
                                   else:
                                       res="500,unexpected error {}".format(doorLockException)
                                       self.send_response(500)
                                       self.end_headers()
                                       self.wfile.write(b'Unexpected error')
                                       log.debug(" Unexpected error")
                                       doorLockException=''


                                else:
                                    res="403,bad request"
                                    self.send_response(403)
                                    self.end_headers()
                                    self.wfile.write(b'BAD Request')
                            # else:
                            #     self.send_response(503)
                            #     self.end_headers()
                            #     self.wfile.write(b'Service Unavailable')
                        except Exception as e:
                            res="412,bad request-{}".format(e)
                            log.debug("Exception raised in /doorLock post request {}".format(e))
                            self.send_response(412)
                            self.end_headers()
                            self.wfile.write(b'BAD Request')
                    else:
                        res="415,bad request"
                        self.send_response(415)
                        self.end_headers()
                        self.wfile.write(b'BAD Request')
                        log.debug(" 415 bad request")
                else:
                        res="412 ,Bad request"
                        self.send_response(412)
                        self.end_headers()
                        self.wfile.write(b'BAD Request')
                        log.debug(" 412 bad request")
                d={"pin": pin, "response": res, "podState": podState}
                if res.__contains__("500") or res.__contains__("412"):
                    data = {"type": "CRITICAL", "deviceType": "Unlock", "name": "Reservation Login", "message": d}
                else:
                    data={"type": "INFO", "deviceType": "Unlock", "name": "Reservation Login","message": d}
                # pindata = {"Reservation Login": {"pin": pin, "response": res, "podState": podState}}
                # mqtt_client.publish('devices/' + pod_id + '/messages/events/', json.dumps(pindata), qos=1)
                mqtt_client.publish('devices/' + pod_id + '/messages/events/', json.dumps(data), qos=1)

        elif None != re.search('/adminHotspotLogin',self.path):
            log.debug("/adminHotspotLogin post request")
            type = self.headers['Content-Type']
            if type == "application/json":
                try:
                    content_length = int(self.headers['Content-Length'])

                    body = self.rfile.read(content_length)
                    log.debug("request body - {}".format(body))

                    data = json.loads(body)
                    if "duration" in data.keys():
                        duration=data.get("duration")
                        if podState == "Admin In Use":
                            log.debug("Admin login via hotspot,state is {}".format(podState))
                            pass
                        else:
                            prevPodState = podState
                            log.debug("Admin timer will trigger after {}".format(duration))
                            setTimeoutMinutes(int(duration), change_prev_pod_state)
                            prePodState = podState
                            podState = "Admin In Use"

                            update_pod_state()
                            mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + grid,
                                            "{\"pod_state\":\"" + podState + "\"}",
                                            qos=1)
                            sensor_status_publish()

                        self.send_response(200)
                        self.end_headers()
                        self.wfile.write(b'Success')
                        log.debug("200 Success")
                    else:

                        res="403,Bad request"
                        self.send_response(403)
                        self.end_headers()
                        self.wfile.write(b'BAD Request')
                        log.debug(" 403 bad request")

                except Exception as e:

                    self.send_response(412)
                    self.end_headers()
                    self.wfile.write(b'BAD Request')
                    log.debug(" 412 bad request {}".format(e))
            else:
                self.send_response(415)
                self.end_headers()
                self.wfile.write(b'BAD Request')
                log.debug(" 415 bad request")


        elif None != re.search('/reservationHotspotLogin', self.path):
            log.debug("/reservationHotspotLogin post request")
            type = self.headers['Content-Type']
            if type == "application/json":
                try:
                    content_length = int(self.headers['Content-Length'])

                    body = self.rfile.read(content_length)
                    log.debug("request body - {}".format(body))

                    data = json.loads(body)
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b'Success')
                    log.debug("200 Success")
                    if "timeOut" in data.keys():
                        timeOut=data.get("timeOut")

                        if podState == "Reservation In Use":
                            pass
                        else:
                            prePodState = podState
                            podState = "Reservation In Use"
                            mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + grid,
                                                "{\"pod_state\":\"" + podState + "\"}",
                                                qos=1)
                            curtime=datetime.datetime.utcnow().replace(microsecond=0)
                            tout=datetime.datetime.strptime(timeOut, "%Y-%m-%d %H:%M:%S")
                            if curtime > tout:
                                print("crxtime is greater")
                                diff = curtime - tout
                            else:
                                print("sensor rxtime is greater")
                                diff = tout - curtime
                            timeOutSeconds = diff.seconds - 60
                            setTimeout(timeOutSeconds, change_pod_state, "TimeOut")
                            update_pod_state()

                            # sensor_status(0)
                            sensor_status_publish()
                            inform_pod_state()


                    else:

                        res = "403,Bad request"
                        self.send_response(403)
                        self.end_headers()
                        self.wfile.write(b'BAD Request')
                        log.debug(" 403 bad request")

                except Exception as e:

                    self.send_response(412)
                    self.end_headers()
                    self.wfile.write(b'BAD Request')
                    log.debug(" 412 bad request {}".format(e))
            else:
                self.send_response(415)
                self.end_headers()
                self.wfile.write(b'BAD Request')
                log.debug(" 415 bad request")

        elif None != re.search('/admindoorLock', self.path):

                log.debug("/admindoorLock post request")

                res = ''
                adminpin = ''
                adminKey = ''
                duraTion = ''
                type = self.headers['Content-Type']
                if type == "application/json":
                    try:
                        content_length = int(self.headers['Content-Length'])


                        body = self.rfile.read(content_length)
                        log.debug("request body - {}".format(body))

                        data = json.loads(body)
                        if "adminpin" in data.keys() and "adminkey" in data.keys() and "duration" in data.keys():
                            adminPin = data.get("adminpin")
                            adminkey=data.get("adminkey")
                            duration=data.get("duration")
                            adminpin=adminPin
                            adminKey=adminkey
                            duraTion=duration
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
                                            dat = {"on": "false"}

                                            # log.debug("data is {}".format(data))
                                            data = json.dumps(dat).encode('utf-8')
                                            req = urllib.request.Request(url+iot_ip + '/devices/' + id, headers=headers, data=data,
                                                                         method="PUT")
                                            resp = urllib.request.urlopen(req,timeout=URL_TIMEOUT)

                                            if (resp.status == 200):
                                                res="200,Door opened"
                                                self.send_response(200)
                                                self.end_headers()
                                                self.wfile.write(b'Door Opened')
                                                # global podState,prevPodState
                                                log.debug("admin login lockstate is {}".format(lockstate))

                                                if lockstate == "enabled":
                                                    lock_door()

                                                # curtime = datetime.datetime.utcnow()
                                                #
                                                # lockTime = curtime+ datetime.timedelta(seconds=LOCK_TIMER)
                                                #
                                                # log.debug("door  unlocked {} ,locked at {}".format(curtime,lockTime))
                                                #
                                                # setTimeout(lockTime, lock_door)
                                                if podState == "Admin In Use":
                                                    log.debug("Admin unlockingthe door,state is {}".format(podState))
                                                    pass
                                                else:
                                                    prevPodState = podState
                                                    prePodState = podState
                                                    log.debug("Admin timer will trigger after {}".format(duration))
                                                    setTimeoutMinutes(int(duration), change_prev_pod_state)
                                                    podState = "Admin In Use"


                                                
                                                    update_pod_state()
                                                    mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + grid,
                                                                        "{\"pod_state\":\"" + podState + "\"}",
                                                                        qos=1)
                                                    sensor_status_publish()
                                                # sensor_status(0)

                                                #Commented out inform pod state no need ot inform salesforce
                                                #inform_pod_state()


                                                # setTimeoutMinutes(int(duration),change_prev_pod_state)
                                            else:
                                                res="500,Failed to reach gateway"
                                                self.send_response(500)
                                                self.end_headers()
                                                self.wfile.write(b'Fail to reach gateway')
                                                log.debug(" Failed to reach gateway")

                                        else:
                                            res="412,No door_lock sensor"
                                            log.debug("door lock device id missing")
                                            self.send_response(412)
                                            self.end_headers()
                                            self.wfile.write(b'No door sensor')
                                            log.debug(" No door sensor")
                                    else:
                                        res="401,UnAuthorized"
                                        self.send_response(401)
                                        self.end_headers()
                                        self.wfile.write(b'UnAuthorized')
                                        log.debug(" UnAuthorised")
                                else:
                                    res="401,UnAuthorized"
                                    self.send_response(401)
                                    self.end_headers()
                                    self.wfile.write(b'UnAuthorized')
                                    log.debug(" UnAuthorised")
                            else:
                                res="500,Admin pin missing"
                                self.send_response(500)
                                self.end_headers()
                                self.wfile.write(b'Admin pin is missing')
                                log.debug(" Admin pin missing")
                        else:
                            res="403,Bad request"
                            self.send_response(403)
                            self.end_headers()
                            self.wfile.write(b'BAD Request')
                            log.debug(" 403 bad request")
                    except Exception as e:
                        res="412,Bad request - {}".format(e)
                        self.send_response(412)
                        self.end_headers()
                        self.wfile.write(b'BAD Request')
                        log.debug(" 412 bad request {}".format(e))
                else:
                    res="415,Bad request"
                    self.send_response(415)
                    self.end_headers()
                    self.wfile.write(b'BAD Request')
                    log.debug(" 415 bad request")
                # pindata = {
                #     "Admin Login": {"adminpin": adminpin, "adminkey": adminKey, "duration": duraTion, "response": res,
                #                     "podState": podState}}
                #
                # mqtt_client.publish('devices/' + pod_id + '/messages/events/', json.dumps(pindata), qos=1)

                pindata={"adminpin": adminpin, "adminkey": adminKey, "duration": duraTion, "response": res,
                                    "podState": podState}
                if res.__contains__("500") or res.__contains__("412"):
                    data = {"type": "CRITICAL", "deviceType": "Unlock", "name": "Admin Login", "message": pindata
                            }
                else:
                    data = {"type": "INFO", "deviceType": "Unlock", "name": "Admin Login", "message":pindata
                        }
                mqtt_client.publish('devices/' + pod_id + '/messages/events/', json.dumps(data), qos=1)

        elif None != re.search('/pod/state',self.path):
            try:
                type = self.headers['Content-Type']
                if type == "application/json":
                    content_length = int(self.headers['Content-Length'])
                    body = self.rfile.read(content_length)

                    log.debug("request body - {}".format(body))

                    data = json.loads(body)
                    if "state" in data.keys():
                        state=data.get("state")
                        prePodState = podState
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
                                                qos=1)
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
            except Exception as e:
                log.debug("Exception /pod/state - {}".format(e))
                self.send_response(415)
                self.end_headers()
                dat = {"status": "BAD request"}
                data = json.dumps(dat).encode("utf-8")
                self.wfile.write(data)

        elif None != re.search('/pod/intrusion', self.path):
                log.debug("headers for /pod/intrusion rrequest {}".format(self.headers))
                type = self.headers['Content-Type']
                if 'Content-Type' in self.headers:
                    if type == "application/json":
                        try:
                            if intruderState == "enabled":
                                content_length = int(self.headers['Content-Length'])
                                body = self.rfile.read(content_length)
                                log.debug("/pod/intrusion body is {}".format(body))
                                bdata = json.loads(body)
                                log.debug("bdata is {}".format(bdata))
                                data = {"on": "true", "color": "red", "level": LIGHTLEV}

                                log.debug("lightState is {},podState is {},prevpodState is {},before pod state - {}".format(state, podState,
                                                                                                      prevPodState,beforePodState))
                                if "human" in bdata.keys():
                                    log.debug("human key is present")
                                    hval = bdata.get("human")
                                    if hval == "yes":
                                        if "intruder" in intrusion:
                                            pass
                                        else:
                                            intrusion.append("intruder")
                                            log.debug("intrusion detected")
                                            mdata = {"type": "INFO", "deviceType": "Webcam", "name": "intruder",
                                                    "message": {"status":"Intruder detected"}
                                                    }
                                            # mqtt_client.publish('devices/' + pod_id + '/messages/events/',
                                            #                     "{\"intruder_alert\": \"Intruder detected \" }",
                                            #                     qos=1)
                                            mqtt_client.publish('devices/' + pod_id + '/messages/events/',
                                                                json.dumps(mdata),
                                                                qos=1)
                                    elif hval == "no":
                                        if "intruder" in intrusion:
                                            intrusion.remove("intruder")


                                    if state == "enabled":
                                        log.debug("state is enabled")
                                        hval = bdata.get("human")
                                        log.debug("hval is {}".format(hval))
                                        if hval == "yes":
                                            log.debug("hval is {}".format(hval))
                                            if podState == "Available" or podState == "Reserved":
                                                log.debug("change color to red")
                                                intrusionDetection=1
                                                intrusionDetectionTime=datetime.datetime.utcnow().replace(microsecond=0)

                                                log.debug("request body is {}".format(data))
                                                req = urllib.request.Request(url + iot_ip + '/groups/id/' + str(group_id),
                                                                             headers=headers, data=json.dumps(data).encode('utf-8'),
                                                                             method="PUT")
                                                resp = urllib.request.urlopen(req,timeout=URL_TIMEOUT)
                                                #####Redblink
                                                setTimeout(5, redblink)

                                            elif podState == "Available in Next 10 min" or podState == "Reserved in Next 10 min":
                                                 if prevPodState == "Available" or prevPodState == "Reserved":
                                                #if beforePodState == "Available":
                                                    intrusionDetection=1

                                                    intrusionDetectionTime = datetime.datetime.utcnow().replace(
                                                        microsecond=0)
                                                    log.debug("request body is {}".format(data))
                                                    req = urllib.request.Request(
                                                        url + iot_ip + '/groups/id/' + str(group_id),
                                                        headers=headers, data=json.dumps(data).encode('utf-8'),
                                                        method="PUT")
                                                    resp = urllib.request.urlopen(req,timeout=URL_TIMEOUT)
                                                    #####Redblink
                                                    setTimeout(5, redblink)
                                        else:
                                            intrusionDetection=0

                                            if podState == "Available":
                                                group_light_change(AVAILCOLOR)
                                            if podState == "Reserved":
                                                group_light_change(RESERVECOLOR)

                                            if podState == "Available in Next 10 min" and prevPodState == "Reserved":
                                                 group_light_change(RESERVECOLOR)
                                            # elif podState == "Reserved in Next 10 min" and prevPodState == "Available":
                                            #     group_light_change(AVAILCOLOR)
                                            elif podState == "Reserved in Next 10 min" and prevPodState == "Reserved":
                                                 group_light_change(RESERVECOLOR)

                                            if podState == "Reserved in Next 10 min" and beforePodState == "Available":
                                                
                                                group_light_change(AVAILCOLOR)





                                    self.send_response(200)
                                    self.end_headers()
                                    self.wfile.write(b'Success')
                                else:
                                    self.send_response(415)
                                    self.end_headers()
                                    self.wfile.write(b'BAD Request')
                            else:
                                data={"detail":"intruder state is {}".format(intruderState)}
                                self.send_response(200)
                                self.end_headers()
                                self.wfile.write(json.dumps(data).encode("utf-8"))
                        except Exception as e:
                            intrusionDetection=0

                            log.debug("exception raised in /pod/intrusion request {}".format(e))
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
                            # device_list(0)
                            devices_list_update()
                            data = json.loads(body)


                            req = urllib.request.Request(url + iot_ip + '/groups/id/' + str(group_id),
                                                         headers=headers, data=json.dumps(data).encode('utf-8'),
                                                         method="PUT")
                            resp = urllib.request.urlopen(req,timeout=URL_TIMEOUT)


                            self.send_response(200);
                            self.end_headers()
                            self.wfile.write(b'Success')
                            # sensor_status(0)
                            sensor_status_publish()



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

                                id = devicelist.__getitem__(sensorName)[0]
                                data = json.loads(body)

                                req = urllib.request.Request(url+iot_ip + '/devices/' + id, headers=headers, data=json.dumps(data).encode('utf-8'), method="PUT")
                                resp = urllib.request.urlopen(req,timeout=URL_TIMEOUT)

                                if resp.status == 200:
                                    self.send_response(200);
                                    self.end_headers()
                                    self.wfile.write(b'Success')

                                    if sensorName == "door_lock":
                                        if "on" in data.keys():
                                            log.debug("door locking  {}".format(data.get("on")))
                                            val = data.get("on")

                                            if val.lower() == "false":
                                                log.debug("door unlocked")
                                                if lockstate == "enabled":
                                                    lock_door()

                                    sensor_status_publish()
                                    # sensor_status(0)

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
        elif None != re.search('/adminAuth', self.path):
            log.debug("/adminAuth request {}".format(self.headers))
            type = self.headers['Content-Type']
            if 'Content-Type' in self.headers:
                if type == "application/json":
                    try:
                        content_length = int(self.headers['Content-Length'])

                        log.debug("content length is {}".format(content_length))
                        body = self.rfile.read(content_length)
                        log.debug("request body - {}".format(body))

                        data = json.loads(body)
                        if "adminpin" in data.keys() and "adminkey" in data.keys():
                            adminPin = data.get("adminpin")
                            adminkey = data.get("adminkey")
                            log.debug("adminpin - {},adminkey - {}".format(adminPin, adminkey))
                            admin_auth = cs.CSClient().get('zenspace/admin_auth')
                            admin_auth_list = admin_auth.get("data")
                            if admin_auth_list != None:
                                availableadminPins = {};
                                for i in admin_auth_list:
                                    availableadminPins.update(i)
                                if adminkey in availableadminPins.keys():
                                    apin = availableadminPins.get(adminkey)
                                    if adminPin == apin:
                                        self.send_response(200)
                                        self.end_headers()
                                        self.wfile.write(b'Success')
                                        log.debug("Success")

                                    else:
                                        self.send_response(401)
                                        self.end_headers()
                                        self.wfile.write(b'UnAuthorized')
                                        log.debug(" UnAuthorised")
                                else:
                                    self.send_response(401)
                                    self.end_headers()
                                    self.wfile.write(b'UnAuthorized')
                                    log.debug(" UnAuthorised")
                            else:
                                self.send_response(500)
                                self.end_headers()
                                self.wfile.write(b'Admin pin is missing')
                                log.debug(" Admin pin pissing")
                        else:
                            self.send_response(403)
                            self.end_headers()
                            self.wfile.write(b'BAD Request')
                            log.debug(" 403 bad request")
                    except Exception as e:
                        self.send_response(412)
                        self.end_headers()
                        self.wfile.write(b'BAD Request')
                        log.debug(" 412 bad request {}".format(e))
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
    global iot_ip,tmpState,doorLockException
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
                        log.debug(" Current time is {}".format(curtime))


                        if (timeIn <= curtime and curtime <= timeOut):

                            validverify = "valid"
                            if devicelist.__contains__("door_lock"):
                                id = devicelist.__getitem__("door_lock")[0]

                                # log.debug("door id is {}".format(d))
                                response = urllib.request.urlopen(url + iot_ip + '/devices/status/' + id,timeout=URL_TIMEOUT)
                                dres = response.read()
                                res = json.loads(dres);
                                dstatus = res.get("deviceStatus")

                                list = res.get("deviceStatus").get("list")
                                currenttime = datetime.datetime.utcnow().replace(microsecond=0)
                                for l in list:

                                    dat = {"on":"false"}
                                    # log.debug("data is {}".format(data))
                                    data = json.dumps(dat).encode('utf-8')
                                    req = urllib.request.Request(url + iot_ip + '/devices/' + id, headers=headers,
                                                                 data=data,
                                                                 method="PUT")
                                    resp = urllib.request.urlopen(req,timeout=URL_TIMEOUT)
                                    if (resp.status == 200):

                                        global podState
                                        prePodState = podState
                                        if podState == "Admin In Use":
                                            tmpState = "Reservation in Use"
                                            #return 212

                                        if podState == "Reservation In Use":
                                            pass
                                        else:
                                            prePodState = podState
                                            podState = "Reservation In Use"
                                            mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + grid,
                                                                "{\"pod_state\":\"" + podState + "\"}",
                                                                qos=1)
                                            currentPin = pin
                                            if curtime > timeOut:
                                                print("crxtime is greater")
                                                diff = curtime-timeOut
                                            else:
                                                print("sensor rxtime is greater")
                                                diff = timeOut-curtime
                                            timeOutSeconds = diff.seconds - 60
                                            setTimeout(timeOutSeconds, change_pod_state, "TimeOut")


                                        log.debug("login - lock state is {}".format(lockstate))
                                        if lockstate == "enabled":
                                            lock_door()

                                        # lockTime = curtime.second + LOCK_TIMER
                                        #
                                        # setTimeout(lockTime, lock_door)
                                        sensor_status_publish()

                                    currenttime = datetime.datetime.utcnow().replace(microsecond=0)
                                    lctimestamp = l.get("rxTime")
                                    lctime = datetime.datetime.utcfromtimestamp(lctimestamp)
                                    if currenttime > lctime:
                                        print("crxtime is greater")
                                        diff = currenttime - lctime
                                    else:
                                        print("sensor rxtime is greater")
                                        diff = lctime - currenttime

                                    diffsec = diff.seconds

                                    if (diffsec < SENSOR_OFFLINE_TIMER):
                                        return 0
                                        pass
                                    else:
                                        log.debug("door lock sensor is unreachable")
                                        if "door_lock" in sensorOffline:
                                            pass
                                        else:
                                            sensorOffline.append("door_lock")
                                            data = {"type": "WARNING", "deviceType": "sensor", "name": "door_lock",
                                                    "message": {"status":"sensor unreachable","Current_UTC":str(currenttime), "Sensor_UTC":str(lctime)}
                                                    }
                                            # mqtt_client.publish('devices/' + pod_id + '/messages/events/',
                                            #                 "{\"door_lock_alert\": \"sensor unreachable ,Current_UTC: {} , Sensor_UTC: {}\" }".format(currenttime,lctime),
                                            #                 qos=1)
                                            mqtt_client.publish('devices/' + pod_id + '/messages/events/',
                                                                json.dumps(data),
                                                                qos=1)

                                        log.debug("In else returning 0")
                                        # return 20
                                        return 0



                                # else:
                                #     log.debug("In else returning 2")
                                #     return 2
                               # log.debug("gaeway response {}".format(resp))
                            else:

                                log.debug("door lock device id missing")
                                if "door_lock" in sensorOffline:
                                    pass
                                else:
                                    data = {"type": "CRITICAL", "deviceType": "sensor", "name": "door_lock",
                                            "message": {"status":"Either IOTgateway is not reachable / door_lock is not commisioned"}
                                            }
                                    # mqtt_client.publish('devices/' + pod_id + '/messages/events/',
                                    #                 "{\"door_lock_alert\": \"sensor missing \" }",
                                    #                 qos=1)
                                    mqtt_client.publish('devices/' + pod_id + '/messages/events/',
                                                        json.dumps(data),
                                                        qos=1)
                                # return 20
                                return 0
                        else:
                              log.debug("valid verify invalid")
                              validverify = "invalid"


                if validverify == "invalid":
                    if admin_auth_list != None:
                        availableadminPins = {};
                        for i in admin_auth_list:
                            availableadminPins.update(i)
                        if pin in availableadminPins.keys():
                            if devicelist.__contains__("door_lock"):
                                id = devicelist.__getitem__("door_lock")[0]

                                # log.debug("door id is {}".format(d))
                                response = urllib.request.urlopen(url + iot_ip + '/devices/status/' + id,timeout=URL_TIMEOUT)
                                dres = response.read()
                                res = json.loads(dres);
                                dstatus = res.get("deviceStatus")

                                list = res.get("deviceStatus").get("list")
                                currenttime = datetime.datetime.utcnow().replace(microsecond=0)
                                for l in list:
                                    lctimestamp = l.get("rxTime")
                                    lctime = datetime.datetime.utcfromtimestamp(lctimestamp)
                                    if currenttime > lctime:
                                        print("crxtime is greater")
                                        diff = currenttime - lctime
                                    else:
                                        print("sensor rxtime is greater")
                                        diff = lctime - currenttime


                                    diffsec = diff.seconds
                                    if (diffsec < SENSOR_OFFLINE_TIMER):
                                        pass
                                    else:
                                        log.debug("door lock sensor is unreachable")
                                        data = {"type": "WARNING", "deviceType": "sensor", "name": "door_lock",
                                                "message": {"status":"sensor unreachable","Current_UTC": str(currenttime),"Sensor_UTC":str(lctime)}
                                                }
                                        # mqtt_client.publish('devices/' + pod_id + '/messages/events/',
                                        #                 "{\"door_lock_alert\": \"sensor unreachable ,Current_UTC: {} , Sensor_UTC: {}\" }".format(currenttime,lctime),
                                        #                 qos=1)
                                        mqtt_client.publish('devices/' + pod_id + '/messages/events/',
                                                            json.dumps(data),
                                                            qos=1)

                            else:
                                log.debug("door lock id is missing")
                                if "door_lock" in sensorOffline:
                                    pass
                                else:
                                    sensorOffline.append("door_lock")
                                    data = {"type": "CRITICAL", "deviceType": "sensor", "name": "door_lock",
                                            "message": {"status":"Either IOTgateway is not reachable / door_lock is not commisioned"}
                                            }
                                    # mqtt_client.publish('devices/' + pod_id + '/messages/events/',
                                    #                 "{\"door_lock_alert\": \"sensor missing \" }",
                                    #                 qos=1)
                                    mqtt_client.publish('devices/' + pod_id + '/messages/events/',
                                                        json.dumps(data),
                                                        qos=1)
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
                            if devicelist.__contains__("door_lock"):
                                id = devicelist.__getitem__("door_lock")[0]

                                # log.debug("door id is {}".format(d))
                                response = urllib.request.urlopen(url + iot_ip + '/devices/status/' + id,timeout=URL_TIMEOUT)
                                dres = response.read()
                                res = json.loads(dres);
                                dstatus = res.get("deviceStatus")

                                list = res.get("deviceStatus").get("list")
                                currenttime = datetime.datetime.utcnow().replace(microsecond=0)
                                for l in list:
                                    lctimestamp = l.get("rxTime")
                                    lctime = datetime.datetime.utcfromtimestamp(lctimestamp)
                                    if currenttime > lctime:
                                        print("crxtime is greater")
                                        diff = currenttime - lctime
                                    else:
                                        print("sensor rxtime is greater")
                                        diff = lctime-currenttime


                                    diffsec = diff.seconds
                                    if (diffsec < SENSOR_OFFLINE_TIMER):
                                        pass
                                    else:
                                        if "door_lock" in sensorOffline:
                                            pass
                                        else:
                                            sensorOffline.append("door_lock")
                                            data = {"type": "WARNING", "deviceType": "sensor", "name": "door_lock",
                                                    "message": {"status":"sensor unreachable","Current_UTC":str(currenttime) ,"Sensor_UTC":str(lctime)}
                                                    }
                                            # mqtt_client.publish('devices/' + pod_id + '/messages/events/',
                                            #                 "{\"door_lock_alert\": \"sensor unreachable ,Current_UTC: {} , Sensor_UTC: {}\" }".format(currenttime,lctime),
                                            #                 qos=1)
                                            mqtt_client.publish('devices/' + pod_id + '/messages/events/',
                                                                json.dumps(data),
                                                                qos=1)

                            else:
                                if "door_lock" in sensorOffline:
                                    pass
                                else:
                                    sensorOffline.append("door_lock")
                                    data = {"type": "CRITICAL", "deviceType": "sensor", "name": "door_lock",
                                            "message": {"status":"Either IOTgateway is not reachable / door_lock is not commisioned"}
                                            }
                                    # mqtt_client.publish('devices/' + pod_id + '/messages/events/',
                                    #                 "{\"door_lock_alert\": \"sensor missing \" }",
                                    #                 qos=1)
                                    mqtt_client.publish('devices/' + pod_id + '/messages/events/',
                                                        json.dumps(data),
                                                        qos=1)
                            return 202
                        else:
                            log.debug("Accessing pin is not present")
                            return getAuthentications(pin, totalpincount)
                    else:
                        return getAuthentications(pin,totalpincount)



        else:

                #return getAuthentications(pin,totalpincount)
                if admin_auth_list != None:
                  availableadminPins = {};
                  for i in admin_auth_list:
                        availableadminPins.update(i)

                  if pin in availableadminPins.keys():
                      if devicelist.__contains__("door_lock"):
                          id = devicelist.__getitem__("door_lock")[0]

                          # log.debug("door id is {}".format(d))
                          response = urllib.request.urlopen(url + iot_ip + '/devices/status/' + id,timeout=URL_TIMEOUT)
                          dres = response.read()
                          res = json.loads(dres);
                          dstatus = res.get("deviceStatus")

                          list = res.get("deviceStatus").get("list")
                          currenttime = datetime.datetime.utcnow().replace(microsecond=0)
                          for l in list:
                              lctimestamp = l.get("rxTime")
                              lctime = datetime.datetime.utcfromtimestamp(lctimestamp)
                              if currenttime > lctime:
                                diff = currenttime - lctime
                              else:
                                  diff = lctime - currenttime
                              diffsec = diff.seconds
                              if (diffsec < SENSOR_OFFLINE_TIMER):
                                  pass
                              else:
                                  data = {"type": "WARNING", "deviceType": "sensor", "name": "door_lock",
                                          "message": {"status":"sensor unreachable","Current_UTC": str(currenttime),"Sensor_UTC":str(lctime)}
                                          }
                                  # mqtt_client.publish('devices/' + pod_id + '/messages/events/',
                                  #                 "{\"door_lock_alert\": \"sensor unreachable ,Current_UTC: {} , Sensor_UTC: {}\" }".format(currenttime,lctime),
                                  #                 qos=1)
                                  mqtt_client.publish('devices/' + pod_id + '/messages/events/',
                                                      json.dumps(data),
                                                      qos=1)

                      else:
                          if "door_lock" in sensorOffline:
                              pass
                          else:
                              sensorOffline.append("door_lock")
                              data = {"type": "CRITICAL", "deviceType": "sensor", "name": "door_lock",
                                      "message": {"status":"Either IOTgateway is not reachable / door_lock is not commisioned"}
                                      }
                              # mqtt_client.publish('devices/' + pod_id + '/messages/events/',
                              #                 "{\"door_lock_alert\": \"sensor missing \" }",
                              #                 qos=1)
                              mqtt_client.publish('devices/' + pod_id + '/messages/events/',
                                                  json.dumps(data),
                                                  qos=1)
                      return 202
                  else:

                      log.debug("Accessing pin is not present")
                      return getAuthentications(pin, totalpincount)
                else:
                     return getAuthentications(pin, totalpincount)
    except Exception as e:
        log.debug("Exception - verifyAuth -{}".format(e))
        doorLockException=e
        return 500

def getAuthentications(pin,count):
    try:

        dat = {"start_datetime": datetime.datetime.strftime(datetime.datetime.utcnow(), "%Y-%m-%d %H:%M:%S"),
               "end_datetime": datetime.datetime.strftime(datetime.datetime.utcnow() + datetime.timedelta(minutes=30),"%Y-%m-%d %H:%M:%S"),
               "localdate":datetime.datetime.now().date()}

        data=urllib.parse.urlencode(dat)
        req = urllib.request.Request(zenurl + pod_id + "/?" + data, headers=headers, method="GET")
        resp = urllib.request.urlopen(req,timeout=URL_TIMEOUT)
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
        try:
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
                # device_list(0)
                devices_list_update()



                # sensor_status(0)
                sensor_status_publish()

            else:
                print("iot ip is present")
        except Exception as e:
            log.debug("Exception - get iot ip - {}".format(e))


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

def get_desired():
    global cpOnlineTime,ppOnlineTime
    try:

        global podState
        cpOnlineTime = datetime.datetime.utcnow().replace(microsecond=0)
        if cpOnlineTime > ppOnlineTime:
            diff = cpOnlineTime - ppOnlineTime
        else:
            diff = ppOnlineTime -cpOnlineTime
        log.debug("cpOnlineTime = {},ppOnlineTime ={},diff ={},diff.seconds - {}".format(cpOnlineTime,ppOnlineTime,diff,diff.seconds))



        if int(diff.seconds) > POD_OFFLINE_TIMER or int(diff.seconds) == 0:

            data = {"type": "INFO", "deviceType": "cradlepoint", "name": "ZenServer",
                "message": {"status":"zenspace back to online"}
                }

            mqtt_client.publish('devices/' + pod_id + '/messages/events/',
                            json.dumps(data),
                            qos=1)
            ppOnlineTime=datetime.datetime.utcnow().replace(microsecond=0)

        # mqtt_client.publish('devices/' + pod_id + '/messages/events/', "{\"ZenServer\":\"zenspace back to online\"}",
        #                     qos=1)
        log.debug("get desired - podState {}".format(podState))
        mqtt_client.subscribe("$iothub/twin/res/#")
        desid = "101"
        mqtt_client.publish('$iothub/twin/GET/?$rid=' + desid, qos=1)
    except Exception as e:
        log.debug("Exception  - get desired {}".format(e))


mqtt_client = mqtt.Client(client_id=pod_id, protocol=mqtt.MQTTv311)


# Assign the appropriate callback functions
mqtt_client.on_connect = on_connect
mqtt_client.on_disconnect = on_disconnect
mqtt_client.on_publish = on_publish
mqtt_client.on_message = on_message
mqtt_client.on_subscribe = on_subscribe
mqtt_client.on_log = on_log


try:
   _thread.start_new_thread(start_server, ())
   get_iot_ip()
   set_state_color()
   log.debug("after state color")
   try:
       log.debug("in main try block")
       if os.path.exists('/var/media'):
           print("path exists")
           log.debug("media exists")
           if os.path.exists('/var/media/auth.ini'):
               print("file exists")
               log.debug("file exists in media..")
               with open('/var/media/auth.ini') as json_file:
                   data1 = json.load(json_file)
                   print(data1)

                   if "pin_auth" in data1.keys():
                       pinAuth = data1.get("pin_auth");
                       count = 0
                       pinAuthList = {}
                       for p in pinAuth:
                           pinAuthList.update(p)
                       for k, v in pinAuthList.items():
                           # data={k:{"TimeIn":v.get("TimeIn"),"TimeOut":v.get("TimeOut")}}
                           data = {k: {"pin": v.get("pin"), "TimeOut": v.get("TimeOut")}}
                           s = cs.CSClient().put('zenspace/pin_auth/' + str(count), data)

                           count = count + 1
                   if "admin_auth" in data1.keys():
                       adminAuth = data1.get("admin_auth");
                       count = 0
                       adminAuthList = {}
                       for a in adminAuth:
                           adminAuthList.update(a)
                       for k, v in adminAuthList.items():
                           data = {k: v}

                           # s = cs.CSClient().post('zenspace/admin_auth/', data)
                           s = cs.CSClient().put('zenspace/admin_auth/' + str(count), data)

                           count = count + 1


           else:
               print("not exists")
               log.debug("media exists,file absent")

       else:
           print("not exists")
           log.debug("media not exists")
   except Exception as e:
       log.debug("Unable to read from flash {}".format(e))

   if iot_hub_name !=None and pod_key !=None and pod_id !=None:
    try:
        mqtt_client.username_pw_set(username=iot_hub_name + '.azure-devices.net/' + pod_id+'/api-version=2018-06-30', password=generate_sas_token(iot_hub_name+".azure-device.net/devices"+pod_id,pod_key,pod_id))

        mqtt_client.tls_set(ca_certs=path_to_root_cert, certfile=None, keyfile=None, cert_reqs=ssl.CERT_REQUIRED,
                            tls_version=ssl.PROTOCOL_TLSv1, ciphers=None)

        mqtt_client.tls_insecure_set(False)

        log.debug("Connecting to hub")
        mqtt_client.connect(iot_hub_name + '.azure-devices.net', port=8883,keepalive=90)
    except Exception as e:
        log.debug("Exception in connecting to hub {}".format(e))

    # _thread.start_new_thread(mqtt_connect,())
    log.debug("hub connected")
    currentdate = datetime.datetime.now().date()
    dt="786"
    mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + dt,
                        "{\"local_date\":\"" + str(currentdate) + "\"}",
                        qos=1)


    #request id to cloud
    grid='1000'
    rs='1200'
    ps='1100'
    log.debug("initial pod state {}".format(podState))

    mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + ps,
                        "{\"pod_state\":\"" + podState + "\"}",
                        qos=1)

    log.debug("initial state is {}".format(state))
    mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + rs,
                        "{\"light_state\":\"" + state + "\"}",
                        qos=1)
    mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + grid,
                        "{\"lock_state\":\"" + lockstate + "\"}",
                        qos=1)
    mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + grid,
                        "{\"fan_state\":\"" + fanState + "\"}",
                        qos=1)
    mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + grid,
                        "{\"timers\": { \"lock_timer\":\"" + str(LOCK_TIMER) + "\"}}",
                        qos=1)
    mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + dt,
                        "{\"intruder_state\":\"" + intruderState + "\"}",
                        qos=1)
    data = {"type": "INFO", "deviceType": "cradlepoint", "name": "ZenServer",
            "message": {"status":"zenspace server started"}
            }
    # mqtt_client.publish('devices/' + pod_id + '/messages/events/',    "{\"ZenServer\":\"zenspace server started\"}",
    #                     qos=1)
    mqtt_client.publish('devices/' + pod_id + '/messages/events/', json.dumps(data),
                        qos=1)

    # inform_pod_state()

    if iot_ip == '' :
        mqtt_client.publish('$iothub/twin/PATCH/properties/reported/?rid=' + grid,
                            "{\"gateway_status\":\"" + "No gateway detected" + "\"}", qos=0)
    else:
        pass

    start=0
    try:
        total_devices=get_number_of_devices()
    except Exception as e:
        log.debug("IOT gateway not reachable {}".format(e))
        total_devices=0
    try:
        # health_monitoring()
        # network_stats()
        gateway_status()
        # print(sensor_check())


        # device_list(start)
        devices_list_update()
    except Exception as e:
        log.debug("Exception - main status calls - {}".format(e))
    if len(deviceslistbyid) == 0:
        pass
    else:
        old_devicelistbyid = deviceslistbyid.copy()
        setInterval(DEVICE_TIMER+120, device_list_manage)


    # sensor_status(start)
    try:
        # sensor_status_publish()
        pod_status()
    except Exception as e:
        log.debug("Exception - main status publish - {}".format(e))
    # setInterval(DEVICE_TIMER, device_list,start)
    setInterval(DEVICE_TIMER, devices_list_update)
    setInterval(POD_TIMER, pod_status)
    setInterval(GATEWAY_TIMER,gateway_status)
    # setInterval(SENSOR_TIMER,sensor_status,start)
    setInterval(SENSOR_TIMER, sensor_status_publish)
    setInterval(CHANGE_TO_STATE_COLOR_TIMER,change_to_state_color,0)
    setInterval(CONN_TIMER,network_stats)
    setInterval(GATEWAY_TIMER,get_iot_ip)
    setInterval(HEALTH_TIMER,health_monitoring)
    # _thread.start_new_thread(start_server, ())

    # setTimeout(DESIRED_TIMER,get_desired)
    mqtt_client.loop_forever()

   else:
       log.error("Hub Name,Pod Id,Pod Key is missing")





except Exception as e:
    log.error('Exception: {}'.format(e))




	
			
			

