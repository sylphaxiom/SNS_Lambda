# SN_Incident_Create.py

Lambda script written in Python to accept SNS Topic alerts and create serviceNow
tickets based off of the alert information. Querying ServiceNow to validate the
alert input prior to submitting the ticket.

- Commonly updated variables are stored in environment, reducing need for code
  changes on standard updates.
- Uses Secret Manager for secure password access to make API calls.
- Queries ServiceNow to validate CI, appID, and Assignment Group prior to
  creating the incident.
- All tickets (except those explicitly listed) create P4 tickets.
  - The listed alert names in the code raise P2 tickets.
- Incident creation details returned from request are stored in logs.

## Installation

Installed into AWS Lambda utilizing Lambda Layers for dependencies and a
requirements.txt file for version/dependency tracking.

### Package setup

1. Create directory for project files:
   `mkdir C:\deploy\SN_incident\`
2. Install requirements.txt
   `py -m pip -r requirements.txt -t python/`
3. Zip python directory
   `Compress-Archive -Path .\python -DestinationPath .\layer.zip`

### Deployment

(AWS procedure obtained from ([documentation]https://docs.aws.amazon.com/lambda/latest/dg/lambda-python.html)
and NOT validated with cloud engineers, please see cloud engineering documentation for guidance)

1. Package dependencies as shown above
2. Create Lambda function
3. Add python code to function
   1. _NOTE_ Verify `BASE` points to correct ServiceNow instance (dev/prod)
      `C:\deploy\SN_Incident\SN_Incident_Create.py`
4. Add layer containing dependencies
   `C:\deploy\SN_Incident\layer.zip`
5. Add environment variables required for execution
   1. Secret Manager ARN (appID/password)
      `'appUser':'<password>'`
   2. Assignment Group
      `'ASSIGN_GRP':'Cloud Operations'`
   3. App ID
      `'APPID':'appUser'`
   4. Base Resource URL
      `'BASE':'https://acme.servicenowservices.com/api/now/table/'`
6. Complete Lambda setup in AWS and activate.

### Updates

Script is designed to require minimal code changes when updates are necessary.
Most changes that would need to be made will be in the environment variables
used by the script. Space to update high priority tickets is in code, but clearly marked.

#### Script Assumptions/Convention Dependencies

There are as few dependencies as possible on the input.

- If alert fields are added or removed
  - Some errors may occur in the variable mapping in the script if fields change.
  - Locate the alert field variables in the `lambda_handler(event, context)` function to make updates
    - If ADDING variables:
      - Make sure to add a corresponding `alertVars` assignment below the
        newly added field variable
      - To add the field to the ticket body, add text and variable to the
        `create_incident(alertVars)` function.
    - If REMOVING variables:
      - Be sure to remove any reference to the variable, particularly in
        the `create_incidents(alertVars)` and `lambda_handler(event, context)` functions.
      - Required variables in body content are:
        - Assignment Group (`alertVars['assignmentGrp']`)
        - cmdb_ci (`alertVars['cmdbCi']`)
        - Caller (`alertVars['callerId']`)
        - Subject (`alertVars['subj']` optionally can be replaced with
          plain text)
        - Urgency (hard coded `2`)
        - Impact (hard coded `3` if `title` not in `highPriTicket` list)
        - Description (string composed of variables/text, optionally can
          be replaced with plain text)
- Dependency on Alert Title format
  - Script is specifically searching for the RegEx pattern: `(i-[\w]+)-([\w]+$)`
    - This will match the instance Id pattern followed by a `-` followed
      by a string of characters that represent the alert name.
    - instance Id is assumed to be an `i-` followed by a string of letter
      and number characters
  - Script does not care about what is before the instance Id.
    - As long as instance Id and alert name are at the end.
    - i.e. `test-i-23048234-HighCPUUtilization`
      - Instance Id: `i-23048234`
      - Alert Name: `HighCPUUtilization`
      - Ignored data: `test-`
