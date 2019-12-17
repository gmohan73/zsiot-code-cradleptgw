APP_NAME='zenspace_iot_gateway'
ZEN_URL='https://zenspace-production.herokuapp.com/api/iot/reservation/retrieve/'
ZEN_STATE_URL='https://zenspace-production.herokuapp.com/api/iot/pod/save-state/'
ZEN_LOGICALNAME_URL="https://zenspace-production.herokuapp.com/api/iot/pod/retrieve/"
HOTSPOT_URL='https://zenspace-production.herokuapp.com/api/iot/pod/accesspoint/access/'

# ZEN_URL='https://zensapce-staging.herokuapp.com/api/iot/reservation/retrieve/'
# ZEN_STATE_URL='https://zensapce-staging.herokuapp.com/api/iot/pod/save-state/'
# ZEN_LOGICALNAME_URL="https://zensapce-staging.herokuapp.com/api/iot/pod/retrieve/"
# HOTSPOT_URL='https://zensapce-staging.herokuapp.com/api/iot/pod/accesspoint/access/'

HOTSPOT_CLIENTS=15
HOTSPOT_METHOD="local"
PORTS=[9001,9002,9003]
WINDOWS_FIREWALL="disabled"
