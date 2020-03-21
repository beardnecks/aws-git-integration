# Git to S3
Originally based on the [AWS quickstart git2s3](https://github.com/aws-quickstart/quickstart-git2s3) stack.

An aws SAM application that uploads git repository to a S3 bucket.

### Linking your Git repository to Amazon S3 and AWS services for continuous code integration, testing, and deployment 

This Quick Start deploys HTTPS endpoints and AWS Lambda functions for implementing webhooks, to enable event-driven integration between Git services and Amazon Web Services (AWS) on the AWS Cloud.

After you deploy the Quick Start, you can set up a webhook that uses the endpoints to create a bridge between your Git repository and AWS services like AWS CodePipeline and AWS CodeBuild. With this setup, builds and pipeline executions occur automatically when you commit your code to a Git repository, and your code can be continuously integrated, tested, built, and deployed on AWS with each change. 

The Quick Start includes an AWS CloudFormation template that automates the deployment. You can also use the AWS CloudFormation template as a starting point for your own implementation.

![Quick Start architecture for implementing webhooks on AWS](https://d0.awsstatic.com/partner-network/QuickStart/datasheets/git-to-s3-webhooks-architecture-on-aws.png)

## Deployment
Prerequisites:
* [SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-install-linux.html) (Installed)
* [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/install-linux.html) (Installed and configured)
* Python
* Docker - Optional (recommended for builds)

To deploy the application using SAM CLI:
```bash
sam build --use-container
sam deploy --guided
```