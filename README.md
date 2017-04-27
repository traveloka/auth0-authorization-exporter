# Auth0 - Authorisation to AWS S3

## Install Extension

This extension will take all Auth0 authorisation defined in authorisation extension and export them to AWS S3. Go to your management dashboard - https://manage.auth0.com/#/extensions and click on Create Extension and enter the url for this github repo.


## Deploy to Webtask.io

### Configure Webtask

If you haven't configured Webtask on your machine run this first:
```
npm i -g wt-cli
wt init
```

### Pre reqs:

> To get a client_id and secret use the client credentials setup and grant a client "read:users read:clients" scope on API V2 and you can use that Client Id/Secret for AUTH0_CLIENT_ID && AUTH0_CLIENT_SECRET in the script below.
> You will need to create an S3 Bucket and S3 Object and user those for S3_BUCKET and S3_FILE_NAME
> Get the AWS Access, Secret Key and Region for AWS_ACCESS_KEY_ID, AWS_SECRET_KEY, AWS_REGION that allows you to send file that bucket.

### Create Cron

To run it on a schedule (run every 5 minutes for example):

```bash
wt cron schedule --profile "wt_profile" --name auth0-logs-2-cloudwatch \
--secret AUTH0_DOMAIN="youauth0domain" \
--secret AUTH0_CLIENT_ID="client_id with read:users and read:clients permissions on API V2" \
--secret AUTH0_CLIENT_SECRET="<client_secret>" 
--secret AUTHORISATION_EXTENSION_API_URL="the url to your authorisatin extension provided in the API section of the extension" \
--secret AWS_REGION="<aws_region>" \
--secret AWS_ACCESS_KEY="aws_access_key" \
--secret AWS_SECRET_KEY="aws_secret_key" \
--secret S3_BUCKET="S3 Bucket Name"
--secret S3_FILE_NAME="File name in S3" --secret CLOUDWATCH_LOG_STREAM_NAME="logStreamName" \
--secret EXCLUDED_CLIENTS="Comma separted list of non interactive clients that don't have users" \
"*/5 * * * *" build/bundle.js
```

## Usage

Go to [S3] to check your file

## Filters

The `EXCLUDED_CLIENTS` can be set with comma separated value of non interacive clients to prevent the tools from getting the user policy for that client.

## Issue Reporting

If you have found a bug or if you have a feature request, please report them at this repository issues section. Please do not report security vulnerabilities on the public GitHub issue tracker.

## Contributors

- Oktaviandi Hadi Nugraha (oktaviandi.nugraha@traveloka.com)

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.
