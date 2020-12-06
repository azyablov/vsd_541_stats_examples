###################################################################################################
### Access Methods
###################################################################################################

### Basic curl health-check
curl -k https://10.87.3.4:8443/nuage/health
curl -s -k https://10.87.3.4:8443/nuage/health | python -m json.tool

### Curl shell script
touch vsd_hc.sh
chmod u+x vsd_hc.sh
cat <<EOT > vsd_hc.sh
#!/bin/bash
for OCT in {4..6} ; do curl -k https://10.87.3.\$OCT:8443/nuage/health -s | python -m json.tool | grep status ; done
EOT

###################################################################################################
### API Versions
###################################################################################################

### Retrieve supported API versions
curl -k -s https://10.87.3.4:8443/nuage | python -m json.tool
curl -k -s https://10.87.2.228:8443/nuage | python -m json.tool

###################################################################################################
### Authentication
###################################################################################################

### Encode credentials (Python3)
python
import base64
base64.b64encode(b'csproot:csproot')

### Encode credentials (Perl)
perl -MMIME::Base64 -e "print encode_base64(\"csproot:csproot\")"

### Request an API Key
curl -s -k -H "X-Nuage-Organization: csp" -H "Authorization: XREST Y3Nwcm9vdDpjc3Byb290" https://10.87.3.4:8443/nuage/api/v6/me | python -m json.tool

### Variables
ORG='X-Nuage-Organization: csp'
API='https://10.87.3.4:8443/nuage/api/v6'
AUTH='Authorization: XREST Y3Nwcm9vdDpjc3Byb290'

### Verify variables
echo $ORG
echo $AUTH
echo $API

### Request an API Key (simplified)
curl -s -k -H "$ORG" -H "$AUTH" $API/me | python -m json.tool

### Encode an API Key
perl -MMIME::Base64 -e "print encode_base64(\"csproot:06e15c4f-28fe-42c3-8887-e37d79b0653f\")"

### Redefine AUTH variable
AUTH='Authorization: XREST Y3Nwcm9vdDowNmUxNWM0Zi0yOGZlLTQyYzMtODg4Ny1lMzdkNzliMDY1M2Y='

### Make sure API calls successfully authenticated
curl -s -k -H "$ORG" -H "$AUTH" $API/enterprises | python -m json.tool

### Mini-script to get API Key and set variables
AUTH='Authorization: XREST Y3Nwcm9vdDpjc3Byb290'
ORG='X-Nuage-Organization: csp'
API='https://10.87.3.4:8443/nuage/api/v6'
APIKey=`curl -s -k -H "$ORG" -H "$AUTH" $API/me | python -m json.tool | grep '"APIKey"' | cut -c20-55`
APIKey_B64=`perl -MMIME::Base64 -e "print encode_base64(\"csproot:$APIKey\")"`
AUTH="Authorization: XREST $APIKey_B64"

###################################################################################################
### Fetching Objects
###################################################################################################

### List all enterprises
curl -s -k -H "$ORG" -H "$AUTH" $API/enterprises | python -m json.tool

### Get all groups in a selected enterprise
curl -s -k -H "$ORG" -H "$AUTH" $API/enterprises/74da05fd-9755-44dc-9e8c-23e9b024915e/groups | python -m json.tool

### Get all users in a selected group
curl -s -k -H "$ORG" -H "$AUTH" $API/groups/05c1fd42-824a-43d0-91af-40807b7fff24/users | python -m json.tool

###################################################################################################
### Creating Objects
###################################################################################################

### Define new variables
TYPE='Content-Type: application/json'
NEW_ENT='{ "name": "Demo", "description": "BWI Workshop Demo" }'
NEW_GROUP='{ "name": "Automation Engineers", "description": "Group for automation staff" }'

### Create new enterprise
curl -s -k -H "$ORG" -H "$AUTH" -H "$TYPE" -X POST -d "$NEW_ENT" $API/enterprises | python -m json.tool

### Create new group within enterprise
curl -s -k -H "$ORG" -H "$AUTH" -H "$TYPE" -X POST -d "$NEW_GROUP" $API/enterprises/f1d4529f-d225-4615-9608-ac0ce46898f6/groups | python -m json.tool

###################################################################################################
### Updating Objects
###################################################################################################

### Define VARS
TYPE='Content-Type: application/json'
NEW_ENT='{ "name": "Demo66" }'

### Update an enterprise
curl -s -k -H "$ORG" -H "$AUTH" -H "$TYPE" -X PUT -d "$NEW_ENT" $API/enterprises/f1d4529f-d225-4615-9608-ac0ce46898f6

###################################################################################################
### Deleting Objects
###################################################################################################

### Delete enterprise
curl -s -k -H "$ORG" -H "$AUTH" -X DELETE $API/enterprises/f1d4529f-d225-4615-9608-ac0ce46898f6 | python -m json.tool

### Delete enterprise + confirm the choice
curl -s -k -H "$ORG" -H "$AUTH" -X DELETE $API/enterprises/f1d4529f-d225-4615-9608-ac0ce46898f6/?responseChoice=1 | python -m json.tool

###################################################################################################
### Filtering Objects
###################################################################################################

### VARS
FILTER="X-Nuage-Filter: name contains 'Nokia'"

### List all enterprises
curl -s -k -H "$ORG" -H "$AUTH" $API/enterprises | python -m json.tool | grep '"name"\|"ID"'

### List filtered enterprises
curl -s -k -H "$ORG" -H "$AUTH" -H "$FILTER" $API/enterprises | python -m json.tool | grep '"name"\|"ID"'

### Advanced filtering
FILTER="X-Nuage-Filter: name == 'Nokia' or description contains 'better'"
curl -s -k -H "$ORG" -H "$AUTH" -H "$FILTER" $API/enterprises | python -m json.tool | grep '"name"\|"ID"'

###################################################################################################
### Push Channel
###################################################################################################

### Start listening to the push channel
curl -s -k -H "$ORG" -H "$AUTH" $API/events | python -m json.tool

### Create an enteprise from other terminal window
curl -s -k -H "$ORG" -H "$AUTH" -H "$TYPE" -X POST -d "$NEW_ENT" $API/enterprises | python -m json.tool

### Request the event
curl -s -k -H "$ORG" -H "$AUTH" $API/events?uuid=0a75b5d6-1e27-4a91-bb43-1d1f8ea2948a | python -m json.tool

###################################################################################################
### API Documentation
###################################################################################################

### URL
https://10.87.3.4:8443/web/docs/api/V6/API.html
https://10.87.3.4:8443/web/docs/api/V5_0/API.html

###################################################################################################
### Underlay Objects
###################################################################################################

### Retriving VSPs
curl -s -k -H "$ORG" -H "$AUTH" $API/vsps | python -m json.tool

### Retrieving VSCs
curl -s -k -H "$ORG" -H "$AUTH" $API/vsps/bc7f86e4-d337-4f24-9043-21395465b4e5/vscs | python -m json.tool

### Retrieving NSGs
curl -s -k -H "$ORG" -H "$AUTH" $API/enterprises | python -m json.tool
curl -s -k -H "$ORG" -H "$AUTH" $API/enterprises/6583bb19-32a9-4a1c-8bad-4ddbd793560d | python -m json.tool
curl -s -k -H "$ORG" -H "$AUTH" $API/enterprises/e78cdc1b-dc0e-422c-a14d-c77acc12820a/nsgateways | python -m json.tool
curl -s -k -H "$ORG" -H "$AUTH" $API/nsgateways/97ffda48-4916-4def-a978-2e22ca56978b/nsports | python -m json.tool
curl -s -k -H "$ORG" -H "$AUTH" $API/nsgateways/97ffda48-4916-4def-a978-2e22ca56978b/nsports | python -m json.tool | grep "[WL]AN"

###################################################################################################
### Overlay Objects
###################################################################################################

### Retrieve all domains
curl -s -k -H "$ORG" -H "$AUTH" $API/domains | python -m json.tool
curl -s -k -H "$ORG" -H "$AUTH" $API/enterprises/e78cdc1b-dc0e-422c-a14d-c77acc12820a/domains | python -m json.tool

### Retrieve enterprise domains (Nokia)
curl -s -k -H "$ORG" -H "$AUTH" $API/domains/e93de2df-017b-4ce5-b6cf-1ae88adf5c8d | python -m json.tool

### Retrieve all subnets
curl -s -k -H "$ORG" -H "$AUTH" $API/subnets | python -m json.tool

### Retrieve domain subnets
curl -s -k -H "$ORG" -H "$AUTH" $API/domains/e93de2df-017b-4ce5-b6cf-1ae88adf5c8d/subnets | python -m json.tool

### Retrieve domain vPorts
curl -s -k -H "$ORG" -H "$AUTH" $API/domains/e93de2df-017b-4ce5-b6cf-1ae88adf5c8d/vports

###################################################################################################
### Alarm Tracking
###################################################################################################

### Request enterprise-level alarms (GOST):
curl -s -k -H "$ORG" -H "$AUTH" $API/enterprises/74da05fd-9755-44dc-9e8c-23e9b024915e/allalarms | python -m json.tool

### Request specific alarm
curl -s -k -H "$ORG" -H "$AUTH" $API/alarms/73ea83f3-4ec8-4369-abc3-94d3a1bec096 | python -m json.tool

### Delete an alarm
curl -s -k -H "$ORG" -H "$AUTH" -X DELETE $API/alarms/73ea83f3-4ec8-4369-abc3-94d3a1bec096 | python -m json.tool

### Request VSC-specific alarm
curl -s -k -H "$ORG" -H "$AUTH" $API/vscs/65ab110b-a07e-4275-ba8b-e157d64d3da5/alarms 

###################################################################################################
### Event Tracking
###################################################################################################

### Retrieve enterprise events
curl -s -k -H "$ORG" -H "$AUTH" $API/enterprises/74da05fd-9755-44dc-9e8c-23e9b024915e/eventlogs | python -m json.tool

### Retrieve VSC events
curl -s -k -H "$ORG" -H "$AUTH" $API/vscs/c7dd748d-a832-4bff-87f3-6867735b63d2/eventlogs | python -m json.tool