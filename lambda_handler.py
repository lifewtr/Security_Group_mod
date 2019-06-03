import json
import logging
import boto3

# initiate logging functionality
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    logger.info(f"Got Event: {event}")
    # required outputs
    sourceip = event['detail']['sourceIPAddress']
    acc_id = event['detail']['userIdentity']['accountId']
    region = event['region']
    event_name = event['detail']['eventName']
    security_group_id = event['detail']['responseElements']['groupId']
    logger.info(f"SecurityGroupId: {security_group_id}, SourceIP: {sourceip}")
    
    # pull out the security group and additional information
    ec2 = boto3.resource('ec2')
    # check if lambda can pull security group successfully
    try:
        sg = ec2.SecurityGroup(security_group_id)
    except botocore.exceptions.ClientError as e:
        exception_type = e.__class__.__name__
        exception_message = str(e)
        api_exception_obj = {
            "isError": True,
            "type": exception_type,
            "message": exception_message
        }
        api_exception_json = json.dumps(api_exception_obj)
        raise LambdaException(api_exception_json)
        
    # check the ip_permissions field in the object for ip addresses and other info
    details = ec2.SecurityGroup(security_group_id).ip_permissions
    logger.info(f"my security group:{details}")
    logger.info(f"my security group id:{sg}")
    logger.info(f"my account id: {acc_id}")
    logger.info(f"my region: {region}")
    logger.info(f"my event name: {event_name}")
    
    # checck for every single security group for info we are looking for
    for agroup in details:
        sg_port = agroup['FromPort']
        sg_ip = agroup['IpProtocol']
        
        # check for the "iprange" field for target ip and port number etc.
        for ipA in agroup['IpRanges']:
            #find out if the ip is what we are looking for.
            if (ipA['CidrIp']=="10.199.237.215/32"):
                logger.info("found target ip")
                logger.info(f"the ip address is: {ipA['CidrIp']}")
                #delete detected security group
                sg.revoke_ingress(GroupId = security_group_id,CidrIp=ipA['CidrIp'], IpProtocol="tcp", FromPort=443, ToPort=443)
                #initiate new security group ingress
                #mysg = ec2.create_security_group(GroupName='afterMod',Description = 'testOutput')
                ## correct error: does not need to create a new security group, just add new ingress
                sg.authorize_ingress(IpProtocol = "tcp", CidrIp = "192.168.209.223/32",FromPort = 443,ToPort = 443)
                sg.authorize_ingress(IpProtocol = "tcp", CidrIp = "192.168.229.197/32",FromPort = 443,ToPort = 443)
