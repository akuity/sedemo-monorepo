# lambda-app

Python AWS Lambda function used in the [beyond-k8s demo](https://github.com/akuity/sedemo-platform/tree/main/apps/beyond-k8s/kargo).

The handler returns a simple JSON response including a `VERSION` environment variable, which is set during deployment to the image tag. This makes it easy to confirm which version is running in each environment during a demo.

## Source

```python
# app.py
def lambda_handler(event, context):
    return {'statusCode': 200, 'body': {'message': 'Hello world!', 'version': os.environ.get('VERSION')}}
```

## Image

Published to ECR: `218691292270.dkr.ecr.us-west-2.amazonaws.com/sedemo/beyond-k8s-lambda`

Published via GitHub Actions using an IAM user with ECR push permissions. See [`beyond-k8s/env/README.md`](../env/README.md) for AWS account and login details.

## Local Development

```bash
docker build -t lambda-app .
docker run -e VERSION=local lambda-app
```

## Role in the Demo

Kargo's `fargate-promote` custom step registers a new ECS task definition pointing to this image whenever a new tag is published. The beyond-k8s pipeline then deploys that task definition to ECS Fargate services across environments — demonstrating Kargo managing workloads outside of Kubernetes.
