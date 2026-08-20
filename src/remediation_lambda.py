import json
import boto3
import os

# Clients for the AWS services this function interacts with
ec2_client = boto3.client('ec2')
dynamodb_client = boto3.client('dynamodb')
sns_client = boto3.client('sns')

# Table name and topic ARN come from the Lambda environment variables
DYNAMODB_TABLE = os.environ.get('TABLE_NAME')
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')


def lambda_handler(event, context):
    try:
        # EventBridge wraps the CloudTrail record inside 'detail'
        detail = event.get('detail', {})
        event_name = detail.get('eventName')

        # We only care about inbound rules being added
        if event_name == 'AuthorizeSecurityGroupIngress':
            request_parameters = detail.get('requestParameters', {})
            group_id = request_parameters.get('groupId')

            # Who made the change, and when
            user_identity = detail.get('userIdentity', {})
            user_arn = user_identity.get('arn', 'Unknown user')
            event_time = detail.get('eventTime', 'Unknown time')
            event_id = detail.get('eventID', 'N/A')

            # CloudTrail may nest the rules under 'items'
            ip_permissions_raw = request_parameters.get('ipPermissions', {})
            ip_permissions = (
                ip_permissions_raw.get('items', [])
                if isinstance(ip_permissions_raw, dict)
                else ip_permissions_raw
            )

            is_vulnerable = False

            for permission in ip_permissions:
                from_port = permission.get('fromPort')
                to_port = permission.get('toPort')

                ip_ranges_raw = permission.get('ipRanges', {})
                ip_ranges = (
                    ip_ranges_raw.get('items', [])
                    if isinstance(ip_ranges_raw, dict)
                    else ip_ranges_raw
                )

                for item in ip_ranges:
                    cidr_ip = item.get('cidrIp')

                    # Vulnerable if SSH is open to the whole internet
                    if from_port == 22 and to_port == 22 and cidr_ip == '0.0.0.0/0':
                        is_vulnerable = True
                        break

            if is_vulnerable:
                print(f"Vulnerability found on {group_id} by {user_arn}. Starting remediation...")

                # 1. Remove the offending rule from the security group
                ec2_client.revoke_security_group_ingress(
                    GroupId=group_id,
                    IpPermissions=[
                        {
                            'IpProtocol': 'tcp',
                            'FromPort': 22,
                            'ToPort': 22,
                            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                        }
                    ]
                )
                print("Rule revoked successfully.")

                # 2. Persist an audit record in DynamoDB
                dynamodb_client.put_item(
                    TableName=DYNAMODB_TABLE,
                    Item={
                        'EventId': {'S': event_id},          # Partition key
                        'Timestamp': {'S': event_time},
                        'UserARN': {'S': user_arn},
                        'SecurityGroupId': {'S': group_id},
                        'ActionTaken': {'S': 'Revoked SSH from 0.0.0.0/0'}
                    }
                )
                print("Audit log written to DynamoDB.")

                # 3. Notify by email through SNS
                message = (
                    f"AWS Security Alert!\n\n"
                    f"User: {user_arn}\n"
                    f"Attempted to open port 22 (SSH) to 0.0.0.0/0 on security group {group_id}.\n\n"
                    f"Automated action: the rule was detected and removed immediately.\n"
                    f"Event time: {event_time}\n"
                    f"Event ID for reference in the database: {event_id}"
                )

                sns_client.publish(
                    TopicArn=SNS_TOPIC_ARN,
                    Subject='Security Alert: SSH Port 22 Open To The World',
                    Message=message
                )
                print("Alert email sent.")

        return {
            'statusCode': 200,
            'body': json.dumps('Processing finished.')
        }

    except Exception as e:
        print(f"An error occurred: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps(f"Internal error: {str(e)}")
        }
