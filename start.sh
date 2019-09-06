#!/bin/bash
cppython installer.py start
cppython hotspotserver.py &
cppython zenspace_iot_gateway.py