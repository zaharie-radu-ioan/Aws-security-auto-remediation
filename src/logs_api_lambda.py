import json
import boto3
import os
from decimal import Decimal


# Helper that serializes DynamoDB numbers into valid JSON
class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return float(obj)
        return super(DecimalEncoder, self).default(obj)


# DynamoDB resource and target table
dynamodb = boto3.resource('dynamodb')
TABLE_NAME = os.environ.get('TABLE_NAME')
table = dynamodb.Table(TABLE_NAME)


def lambda_handler(event, context):
    try:
        # scan() returns every record in the table
        response = table.scan()
        items = response.get('Items', [])

        # CORS headers, needed if the API is called from a web frontend
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Content-Type',
            'Access-Control-Allow-Methods': 'OPTIONS,GET'
        }

        return {
            'statusCode': 200,
            'headers': headers,
            'body': json.dumps(items, cls=DecimalEncoder)
        }

    except Exception as e:
        print(f"Error reading from the database: {e}")
        return {
            'statusCode': 500,
            'headers': {
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({'error': 'Could not retrieve the data.'})
        }
