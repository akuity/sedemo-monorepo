import os
import json

def lambda_handler(event, context):
    print(event)
    print(context)
    return {
        'statusCode': 200,
        'body': json.dumps({
            'message': 'Hello world!',
            'version': os.environ.get('VERSION'),
        })
    }
