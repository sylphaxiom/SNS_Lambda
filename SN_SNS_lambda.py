import json
import os
import requests
import logging
import boto3
import re

#########################################
#                                       #
#       For Local Testing ONLY          #
#                                       #
#########################################
#                                         #
# event = {                               # i-23048234
#         "Records": [                    #
#             {                           #
#                 "EventSource": "aws:sns",
#                 "EventVersion": "1.0",
#                 "EventSubscriptionArn": "arn:aws:sns:us-east-1:<REDACTED_VALUE>:sns-serversupport-alarms:15c57d6d-d883-4fe6-9fc7-0e712df819f4",
#                 "Sns": {
#                     "Type": "Notification",
#                     "MessageId": "1658cb3b-3408-5f0e-a60c-aad0335a8fac",
#                     "TopicArn": "arn:aws:sns:us-east-1:<REDACTED_VALUE>:sns-serversupport-alarms",
#                     "Message": "{\"AlarmName\":\"test-i-0bc38ee1abd2284fe-HighCPUUtilization\",\"AlarmDescription\":\"Testing alarms!\",\"AWSAccountId\":\"<REDACTED_VALUE>\",\"AlarmConfigurationUpdatedTimestamp\":\"2026-01-21T16:53:47.069+0000\",\"NewStateValue\":\"ALARM\",\"NewStateReason\":\"Threshold Crossed: 1 out of the last 1 datapoints [12.15 (21/01/26 16:55:00)] was less than the threshold (99.0) (minimum 1 datapoint for OK -> ALARM transition).\",\"StateChangeTime\":\"2026-01-21T16:55:46.266+0000\",\"Region\":\"US East (N. Virginia)\",\"AlarmArn\":\"arn:aws:cloudwatch:us-east-1:<REDACTED_VALUE>:alarm:test-i-0bc38ee1abd2284fe-HighCPUUtilization\",\"OldStateValue\":\"INSUFFICIENT_DATA\",\"OKActions\":[],\"AlarmActions\":[\"arn:aws:sns:us-east-1:<REDACTED_VALUE>:sns-serversupport-alarms\"],\"InsufficientDataActions\":[],\"Trigger\":{\"MetricName\":\"CPUUtilization\",\"Namespace\":\"AWS/EC2\",\"StatisticType\":\"Statistic\",\"Statistic\":\"AVERAGE\",\"Unit\":null,\"Dimensions\":[{\"value\":\"i-0bdfd1d9cc7426bcb\",\"name\":\"InstanceId\"}],\"Period\":10,\"EvaluationPeriods\":1,\"DatapointsToAlarm\":1,\"ComparisonOperator\":\"LessThanThreshold\",\"Threshold\":99.0,\"TreatMissingData\":\"missing\",\"EvaluateLowSampleCountPercentile\":\"\"}}",
#                     "Timestamp": "2026-01-21T16:55:46.303Z",
#                     "SignatureVersion": "1",
#                     "Signature": "QhTIxzT0XyPMaXkWXcpQfhALROLRhgd+kgbroRZqMU6k0vj65s6sTun57PVBJDlGZjDHS/Fz9NBOhCbTTWGt2Ls0kXG4jWimy/1Ebgzm8DGGRI1q0XjyaLs2/RJaj/PxCdd6xzlyOtwwk8CwusyrBip1B0dnJN32s6Vrn55mQd8eqvIPht5DjSkTz1nN7NbSk8sz4KolkE6BCQcbrPedlN0xJT1aYclB7tUYflRVKrLwTjHMRO7QV8nbIHxEBvhC5iK6TFJdCSzdp8IP9A8OuULBNCOV8JtFAC5SUHcPt6tFJ8JcYYHsyHE28jGgekKMuyep+i5AEoppASJHz5E/FQ==",
#                     "SigningCertUrl": "https://sns.us-east-1.amazonaws.com/SimpleNotificationService-7506a1e35b36ef5a444dd1a8e7cc3ed8.pem",
#                     "Subject": "ALARM: \"test-i-0bc38ee1abd2284fe-HighCPUUtilization\" in US East (N. Virginia)",
#                     "UnsubscribeUrl": "https://sns.us-east-1.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=arn:aws:sns:us-east-1:<REDACTED_VALUE>:sns-serversupport-alarms:15c57d6d-d883-4fe6-9fc7-0e712df819f4",
#                     "MessageAttributes": {}
#                 }                       #
#             }                           #
#         ]                               #
#     }                                   #
# context = None                          #
#                                         #
#########################################
#                                       #
#       For Local Testing ONLY          #
#                                       #
#########################################

# Initialize the logger
log = logging.getLogger(__name__)

# Set log level to INFO for all standard messages DEBUG for additional context
# Default to DEBUG for development, INFO for production
# Unsure if this basicConfig will cause an issue with Lambda logging
# logging.basicConfig(filename='SN_Incident_create.log', level=logging.DEBUG)
# No log output was noted in logs so removed basicConfig()
log.setLevel(logging.DEBUG)

# Function to obtain secret information regardless of location
def get_secret():
    envPass = os.getenv('PWD_P', '')
    if(envPass):
        log.info(f'Located secret in local environment.')
        return envPass
    else:
        log.debug(f'Obtaining secret from extension...')
        client = boto3.client('secretsmanager')
        # Update this if Secret Manager ARN changes
        secName = '<REDACTED_VALUE>'   # Update me with ARN or name of secret
        response = client.get_secret_value(SecretId=secName)
        try:
            log.debug(f'Attempting to obtain secret value...')
            secStr = response['SecretString']
        except Exception as e:
            log.error(f'Unable to obtain secret from Secret Manager\n{e}')
            raise
        
        try:
            log.debug(f'Loading secret to dict object...')
            secDict = json.loads(secStr)
        except Exception as e:
            log.error(f'An error occurred while loading JSON to a dictionary.\n{e}')
            raise

        try:
            log.debug(f'Obtaining final secret from dictionary...')
            secret = secDict[APPID]
        except Exception as e:
            log.error(f'An error occurred while trying to obtain final secret.\n{e}')
            raise

        return secret

# Here are some global variables
ASSIGN_GRP = "Cloud Operations"                                         # UPDATE with assignment group
APPID = "appUser"                                                       # UPDATE with appID sending requests
PWD = get_secret()                                                      # Gets secret from Secret Manager
BASE = "https://acme.servicenowservices.com/api/now/table/"             # This is the dev url


#########################################
#                                       #
#       Priority 2 Ticket List          #
#       Add new checks that require     #
#       a P2 here. All others will      #
#       be sent as P4                   #
#                                       #
#########################################
                                        #
highPriTicket = [                       #
    'HighCPUUtilization',               #
]                                       #
                                        #
#########################################

# Global Alert Variable Dictionary
# If any additional variables are added, make sure to add them to this dict
# in lambda_handler(). This is how the varables are passed to the functions
alertVars = {}

# Handler function to parse input, gather incident data, and create the incident
def lambda_handler(event, context):

    # Pull in necessary bits and make them variables to work with
    try:
        records = event['Records'] # Array of dicts
        for rec in records:
            eventSource = rec['EventSource'] ########DEBUG#######
            alertVars['eventSource'] = eventSource
            eventVersion = rec['EventVersion'] ########DEBUG#######
            alertVars['eventVersion'] = eventVersion
            eventSub = rec['EventSubscriptionArn'] ########DEBUG#######
            alertVars['eventSub'] = eventSub
            meatNTater = rec['Sns'] # This one has all the goodies in it
            # Variables from SNS message
            alarmType = meatNTater['Type'] ########DEBUG#######
            alertVars['alarmType'] = alarmType
            msgId = meatNTater['MessageId'] # Use this value for unique ID to handle dupes (unecessary?)
            alertVars['msgId'] = msgId
            topicARN = meatNTater['TopicArn'] ########DEBUG#######
            alertVars['topicARN'] = topicARN
            timestamp = meatNTater['Timestamp'] ####################
            alertVars['timestamp'] = timestamp
            signVersion = meatNTater['SignatureVersion'] ########DEBUG#######
            alertVars['signVersion'] = signVersion
            signature = meatNTater['Signature'] ########DEBUG#######
            alertVars['signature'] = signature
            signCert = meatNTater['SigningCertUrl'] ########DEBUG#######
            alertVars['signCert'] = signCert
            subj = meatNTater['Subject'] ########DEBUG#######
            alertVars['subj'] = subj
            unsub = meatNTater['UnsubscribeUrl'] ####################
            alertVars['unsub'] = unsub
            # msgAttributes = meatNTater['MessageAttributes']
            # alertVars['msgAttributes'] = msgAttributes
            msgBody = meatNTater['Message'] # This is the alarm data. Make it look nice.
            # Variables from Message Body
            # Drop off single quotes at begin and end of msgBody
            msgBody = json.loads(msgBody)
            alarmName = msgBody['AlarmName'] ####################
            alertVars['alarmName'] = alarmName
            alarmDesc = msgBody['AlarmDescription'] ####################
            alertVars['alarmDesc'] = alarmDesc
            acctId = msgBody['AWSAccountId'] ####################
            alertVars['acctId'] = acctId
            cfgUpdateTS = msgBody['AlarmConfigurationUpdatedTimestamp'] ####################
            alertVars['cfgUpdateTS'] = cfgUpdateTS
            newState = msgBody['NewStateValue'] ####################
            alertVars['newState'] = newState
            stateReason = msgBody['NewStateReason'] ####################
            alertVars['stateReason'] = stateReason
            stateChgTime = msgBody['StateChangeTime'] ####################
            alertVars['stateChgTime'] = stateChgTime
            region = msgBody['Region'] ####################
            alertVars['region'] = region
            alarmARN = msgBody['AlarmArn'] ####################
            alertVars['alarmARN'] = alarmARN
            oldState = msgBody['OldStateValue'] ####################
            alertVars['oldState'] = oldState
            # okActions = msgBody['OKActions'] # Array
            # alertVars['okActions'] = okActions
            # alarmActions = msgBody['AlarmActions'] # Array
            # alertVars['alarmActions'] = alarmActions
            # insufActions = msgBody['InsufficientDataActions'] # Array
            # alertVars['insufActions'] = insufActions
            trigger = msgBody['Trigger']
            # Variables form Trigger
            metricName = trigger['MetricName'] ####################
            alertVars['metricName'] = metricName
            namespace = trigger['Namespace'] ####################
            alertVars['namespace'] = namespace
            statType = trigger['StatisticType'] ####################
            alertVars['statType'] = statType
            stat = trigger['Statistic'] ####################
            alertVars['stat'] = stat
            unit = trigger['Unit'] ####################
            alertVars['unit'] = unit
            dimensions = trigger['Dimensions'] # Array of dict  ####################
            alertVars['dimensions'] = dimensions
            period = trigger['Period'] ####################
            alertVars['period'] = period
            evalPeriod = trigger['EvaluationPeriods'] ####################
            alertVars['evalPeriod'] = evalPeriod
            dataPts = trigger['DatapointsToAlarm'] ####################
            alertVars['dataPts'] = dataPts
            compOper = trigger['ComparisonOperator'] ####################
            alertVars['compOper'] = compOper
            threshold = trigger['Threshold'] ####################
            alertVars['threshold'] = threshold
            treatMissData = trigger['TreatMissingData'] ####################
            alertVars['treatMissData'] = treatMissData
            evalLowSamplePct = trigger['EvaluateLowSampleCountPercentile'] ####################
            alertVars['evalLowSamplePct'] = evalLowSamplePct

            # Parse AlarmName for instance ID and alarm title
            # Additional logic to check for instance and title rather than blind pull
            #
            # Search the name for 'i-<any_letter_or_number_1_or_more_times>' 
            # and '<any_letter_or_number_1_or_more_times_at_the_end>' with a '-' between
            # the patterns. These are the instance and title values.
            alarmBits = re.search(r'(i-[\w]+)-([\w]+$)', alarmName)
            try:
                instanceId = alarmBits.groups()[0]
                log.debug(f'Instance ID is: {instanceId}')
                alarmTitle = alarmBits.groups()[1]
                log.debug(f'Alarm Title is: {alarmTitle}')
                alertVars['instanceId'] = instanceId
                alertVars['alarmTitle'] = alarmTitle
            except Exception as e:
                log.error(f'An error occurred when trying to assign InstanceID and Alarm Title')
                log.error(f'Error output as follows: {e}')

        log.debug(f'******************************************')
        log.debug(f'*** Event Validation/Trace Information ***')
        log.debug(f'******************************************')
        log.debug(f'Event Source        :   {eventSource}')
        log.debug(f'Event Version       :   {eventVersion}')
        log.debug(f'Event Subscription  :   {eventSub}')
        log.debug(f'Alert Topic ARN     :   {signature}')
        log.debug(f'Signature Version   :   {signVersion}')
        log.debug(f'Signing Cert URL    :   {signCert}')
        log.debug(f'Topic ARN           :   {topicARN}')

    except Exception as e:
        log.exception(f'An exception has occurred while parsing the input into variables: {e}')
        raise

    finally:
        if context != None:
            log.debug(f'Function Name       :   {context.function_name}')
            log.debug(f'Function Version    :   {context.function_version}')
            log.debug(f'Calling Resource    :   {context.invoked_function_arn}')
            log.debug(f'Allocated Memory    :   {context.memory_limit_in_mb}')
            log.debug(f'Invoking Request    :   {context.aws_request_id}')
            log.debug(f'Log Grouping        :   {context.log_group_name}')
            log.debug(f'Log Stream          :   {context.log_stream_name}')

        log.info(f'Handler function variables assigned')

    # Validate the AppID, assignment group, and CI
    # to make sure they're present and active
    callerId = get_caller_id()
    alertVars['callerId'] = callerId
    assignmentGrp = get_assignment_grp()
    alertVars['assignmentGrp'] = assignmentGrp
    cmdbCi = get_cmdb_ci(instanceId)
    alertVars['cmdbCi'] = cmdbCi
    log.debug(f'Caller ID found is: {callerId}')
    log.debug(f'Assignment Group found is: {assignmentGrp}')
    log.debug(f'CI found is: {cmdbCi}')

    # Make the magic happen
    create_incident(alertVars)

# Validates the APPID global variable as present and active in ServiceNow
def get_caller_id():
    headers={
        "Content-Type":"application/json",
        "Accept":"application/json"
    }

    # Query parameters on sys_user table:
    #   user_name = APPID
    #   active = true
    URL = f"{BASE}sys_user?sysparm_query=user_name={APPID}^active=true"

    req = requests.get(URL,auth=(APPID,PWD), headers=headers)

    # Check for 200 or WARNING
    if (req.status_code == 200):
        try:
            # Try to parse response
            response = req.json()
        except requests.exceptions.JSONDecodeError:
            # Input is unexpected format, Raise exception
            log.error(f"An error occurred! Response text: {req.text}")
            raise
        for usr in response['result']:
            # Verify user is found and assign
            if usr['user_name'] == APPID:
                log.info(f'Validated production username present and active: {usr['active']}')
                caller_id = usr['sys_id']
        if caller_id:
            # If the caller_id was found, return it.
            log.info(f'caller {caller_id} has been located and validated')
            return caller_id
        else:
            # Caller Id wasn't returned, Raise exception
            log.error(f'Something went wrong; the caller_id is missing!')
            log.error(f'Resposne is: {response}')
            raise
    else:
        # Using Warning since it could be another 200 error or 300 error
        log.warning(f'Something went wrong; the response code was something other than 200')
        log.warning(f'Response code: {req.status_code}')
        log.warning(f'Response text: {req.text}')

# Validates the ASSIGN_GRP global variable as present and active in ServiceNow
def get_assignment_grp():
    assignee = ASSIGN_GRP.replace(' ', '%20') # Replace blank space with %20 so it is URL safe
    headers={
        "Content-Type":"application/json",
        "Accept":"application/json"
    }

    # Query parameters on sys_user_group table:
    #   name = ASSIGN_GRP (url safe)
    #   active = true
    URL = f"{BASE}sys_user_group?sysparm_query=active=true^name={assignee}"

    req = requests.get(URL,auth=(APPID,PWD), headers=headers)
    
    # Check for 200 or WARNING
    if (req.status_code == 200):
        try:
            # Try to parse JSON
            response = req.json()
        except requests.exceptions.JSONDecodeError:
            # Input is unexpected format, Raise exception
            log.error(f"An error occurred! Response text: {req.text}")
            raise
        if (len(response['result']) > 1):
            # THERE CAN BE ONLY ONE!
            log.warning(f'Something went wrong; there is more than one returned value: {response['result']}')
            log.warning(f'Proceeding with grabbing first returned value...')
        if (response['result'][0]['active']):
            # If it's active, assign it
            assignment_grp = response['result'][0]['name']
            # Verify present and active
            if assignment_grp:
                # If the caller_id was found, return it.
                log.info(f'Assignment group {assignment_grp} has been located and validated.')
                return assignment_grp
            else:
                # Caller Id wasn't returned, Raise exception
                log.error(f'Something went wrong; the assignment group wasn\'t found!')
                log.error(f'Resposne is: {response}')
                raise
    else:
        # Using Warning since it could be another 200 error or 300 error
        log.warning(f'Something went wrong; the response code was something other than 200')
        log.warning(f'Response code: {req.status_code}')
        log.warning(f'Response text: {req.text}')

# Lookup CI from instance ID and grab sys_id
def get_cmdb_ci(instanceId):

    # Query parameters on sys_user_group table:
    #   name = ASSIGN_GRP (url safe)
    #   active = true
    URL = f"{BASE}cmdb_ci?sysparm_query=install_status!=7^name={instanceId}"
    headers={
        "Content-Type":"application/json",
        "Accept":"application/json"
    }

    req = requests.get(URL,auth=(APPID,PWD), headers=headers)
    # Check for 200 or WARNING
    if (req.status_code == 200):
        try:
            # Try to parse JSON
            response = req.json()
        except requests.exceptions.JSONDecodeError:
            # Input is unexpected format, Raise exception
            log.error(f"An error occurred! Response text: {req.text}")
            raise
        if (len(response['result']) != 1):
            # THERE CAN BE ONLY ONE!
            log.warning(f'Something went wrong; there is more than one returned value: {response['result']}')
            log.warning(f'Proceeding with grabbing first returned value...')
            cmdb_ci = ''
        else:
            # Assign the sys_id
            cmdb_ci = response['result'][0]['sys_id']
        if cmdb_ci:
            # If it was found, return it
            log.info(f'CMDB CI {response['result'][0]['name']} ({cmdb_ci}) has been located and validated')
            return cmdb_ci
        else:
            # Caller Id wasn't returned, but that's ok
            log.warning(f'Something went wrong; the CI wasn\'t found!')
            log.warning(f'Resposne is: {response}')
    else:
        # Using Warning since it could be another 200 error or 300 error
        log.warning(f'Something went wrong, the response code was something other than 200')
        log.warning(f'response code: {req.status_code}')
        log.warning(f'response text: {req.text}')

def create_incident(alertVars):

    # Pull what you need from alertVars when you need it
    sender = alertVars['callerId']
    group_name = alertVars['assignmentGrp']
    cmdb_ci = alertVars['cmdbCi']
    title = alertVars['alarmTitle']
    alarmType = alertVars['alarmType']
    instanceId = alertVars['instanceId']
    newState = alertVars['newState']
    oldState = alertVars['oldState']
    stateReason = alertVars['stateReason']
    stateChgTime = alertVars['stateChgTime']
    timestamp = alertVars['timestamp']
    metricName = alertVars['metricName']
    namespace = alertVars['namespace']
    statType = alertVars['statType']
    stat = alertVars['stat']
    unit = alertVars['unit']
    dimensions = alertVars['dimensions']
    period = alertVars['period']
    evalPeriod = alertVars['evalPeriod']
    dataPts = alertVars['dataPts']
    compOper = alertVars['compOper']
    threshold = alertVars['threshold']
    treatMissData = alertVars['treatMissData']
    evalLowSamplePct = alertVars['evalLowSamplePct']
    alarmName = alertVars['alarmName']
    alarmDesc = alertVars['alarmDesc']
    acctId = alertVars['acctId']
    cfgUpdateTS = alertVars['cfgUpdateTS']
    unsub = alertVars['unsub']
    alarmARN = alertVars['alarmARN']
    region = alertVars['region']
    urgency = 2
    impact = 1 if title in highPriTicket else 3
    subject = alertVars['subj']
    description = (
        f'There is a new {title} {alarmType} from instance {instanceId}\n\n'
        f'State has updated to {newState} from {oldState} at {stateChgTime}\n'
        f'\tTimestamp: {timestamp}\n'
        f'\tReason: {stateReason}\n'
        f'\tTrigger Information:\n'
        f'\t\t- Metric Name: {metricName}\n'
        f'\t\t- Namespace: {namespace}\n'
        f'\t\t- Statistic Type: {statType}\n'
        f'\t\t- Statistic: {stat}\n'
        f'\t\t- Unit: {unit}\n'
        f'\t\t- Dimensions: {json.dumps(dimensions)}\n'
        f'\t\t- Period: {period}\n'
        f'\t\t- Evaluation Periods: {evalPeriod}\n'
        f'\t\t- Datapoints To Alarm: {dataPts}\n'
        f'\t\t- Comparison Operator: {compOper}\n'
        f'\t\t- Threshold: {threshold}\n'
        f'\t\t- Treat Missing Data: {treatMissData}\n'
        f'\t\t- Evaluate Low Sample Count Percentile: {evalLowSamplePct}\n\n'
        f'Additional alarm information:\n'
        f'\t- Alarm Name: {alarmName}\n'
        f'\t- Alarm Description: {alarmDesc}\n'
        f'\t- Account ID: {acctId}\n'
        f'\t- Alarm ARN: {alarmARN}\n'
        f'\t- Region: {region}\n'
        f'\t- Alarm Configuration Updated Timestamp: {cfgUpdateTS}\n'
        f'\t- Unsubscribe Link: {unsub}'
    )
    
    URL = f"{BASE}incident?sysparm_fields=sys_id%2Cnumber"
    headers={
        "Content-Type":"application/json",
        "Accept":"application/json"
    }
    body = {
        "assignment_group":group_name,
        "cmdb_ci":cmdb_ci,
        "u_affected_user":sender,
        "caller_id":sender,
        "caller":sender,
        "urgency":urgency,
        "impact":impact,
        "description":description,
        "short_description":subject,
        "parent":""
    }

    req = requests.post(URL,json=body,auth=(APPID,PWD), headers=headers)

    # Check for 200 or WARNING
    if (req.status_code == 201):
        try:
            # Try to parse JSON
            response = req.json()
        except requests.exceptions.JSONDecodeError:
            # Input is unexpected format, Raise exception
            log.error(f"an error occurred! Response text: {req.text}")
            raise
        # Add response for logging
        sys_id = response['result']['sys_id']
        inc_number = response['result']['number']
        if sys_id or inc_number:
            # Log the response
            log.info(f'INC: {inc_number} was created with sys_id of {sys_id}')
        else:
            # Log a warning if no sys_id or inc_number
            log.warning(f'Something went wrong! Resposne is: {response}')
    else:
        # Using Warning since it could be another 200 error or 300 error
        log.warning(f'Something went wrong, the response code was something other than 200')
        log.warning(f'response code: {req.status_code}')
        log.warning(f'response text: {req.text}')


#########################################
#                                       #
#       For Local Testing ONLY          #
#                                       #
#########################################
#                                         #
# if __name__ == "__main__":              #
#     lambda_handler(event,context)       #
#                                         #
#########################################
