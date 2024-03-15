# Setup steps

1. Create an IAM user and add following permissions:
    - AmazonEC2ContainerRegistryPowerUser
    - SecretsManagerReadWrite
    - AmazonSNSFullAccess

2. Create a private Elastic Container Registry (ECR) to store the container image
    
    **Important:** Please make sure to use appropriate aws region and use the same region across all the services used for this asset

3. Create a blank github repository and make sure you have a "main" branch. Create one more feature/develop branch from main branch.

4. Goto repo settings > Secrets and variables > Actions. Add the below mentioned repo secrets and variables:
    - Repository secrets
        - ANYPOINT_CLIENT_ID
        - ANYPOINT_CLIENT_SECRET
        - ANYPOINT_ORG_ID
        - AWS_ACCESS_KEY
        - AWS_SECRET_KEY
    - Repository variables
        - ANYPOINT_ENV
        - AWS_ECR_IMAGE_TAG        [You can provide any name which will be tagged to the container image]
        - AWS_ECR_REPOSITORY_NAME  [This is the aws ecr repo name]
        - AWS_REGION
        - AWS_SNS_TOPIC_ARN        [aws sns topic arn which will be used to send email alerts]

    **Important:** Please make sure that the anypoint credentials have sufficient access to modify the dedicated load balancer
    *Note:*  You might not know some of the repo variables at this point, please keep some placeholder for now and you'll be able to get the values by the end of these steps.

5. Now, push the project files to the feature/develop branch and raise a PR and merge into the main branch. This will trigger the github workflow which will build and push the image to AWS ECR.

6. On AWS console, create a lambda function using the container image selecting the image pushed on the ECR in the previous step. Now, goto the Configuration section of lambda and make this changes:
    - General configuration: Change memory to 500 MB and Timeout to 15 min
    - Environment variables: Add an env variable TIME_WINDOW_IN_HRS and set the value as 24 (or whatever time window you want the function to check for new/updated certificates)

7. Create a standard SNS topic and create an Email subscription on this topic. Complete the verification step for this email.
    *Note:* Please add this SNS topic ARN in the github repo variable AWS_SNS_TOPIC_ARN

8. Create an EventBridge Schedule which will trigger the lambda function on recurring basis, making sure the recurring interval is same as the time window you provided in the lambda function (TIME_WINDOW_IN_HRS)