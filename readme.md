# detect-change-security-group-aws

Detecting change and modifying security group in with lambda function

## Primary usage

- Detect a change in security group rules within the target EC2 instance 

- Find any unwanted inbound access ip addresses 

- Revert the change to keep information secure

## Components & Libraries

- AWS Cloudwatch

- AWS Lambda

- AWS IAM role

- boto3

- json

## Permissions

In order to perform desired actions, several permission should be given to the lambda function:

- permission to write tosecurity groups

## Procedure

* Detect a change/new security group inbound rule, then pass on to lambda event

* Check if the ip address, port number and protocol complies with the target

* If so, delete the most recently added security group inbound rule, and add the desired inbound rules back to the security group

