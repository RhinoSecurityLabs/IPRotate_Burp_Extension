# IPRotate_Burp_Extension

Extension for Burp Suite which uses AWS API Gateway to change your IP on every request.

More info: [Bypassing IP Based Blocking Using AWS - Rhino Security Labs](https://rhinosecuritylabs.com/aws/bypassing-ip-based-blocking-aws/)

## Description

This extension allows you to easily spin up API Gateways across multiple regions. All the Burp Suite traffic for the targeted host is then routed through the API Gateway endpoints which causes the IP to be different on each request. (There is a chance for recycling of IPs but this is pretty low and the more regions you use the less of a chance).

This is useful to bypass different kinds of IP blocking like bruteforce protection that blocks based on IP, API rate limiting based on IP or WAF blocking based on IP etc.

## Usage

A version of this is available in the BApp store which you can install from there directly: https://portswigger.net/bappstore/2eb2b1cb1cf34cc79cda36f0f9019874

### With Python2 ENV set

1. Setup [Jython](https://www.jython.org/download.html) in Burp Suite.
3. Ensure you have a set of AWS keys that have full access to the API Gateway service. This is available through the free tier of AWS.
4. Insert the credentials into the fields.
5. Insert the target domain you wish to target.
6. Select HTTPS if the domain is hosted over HTTPS.
7. Select all the regions you want to use, if you leave them all selected all valid regions will automatically be enabled.(The more you use the larger the IP pool will be)
8. Click "Enable".
9. Once you are done ensure you click disable to delete all the resources which were started.

If you want to check on the resources and enpoints that were started or any potential errors you can look at the output console in Burp.

### Without Python2 ENV set (Advanced)

Use helper script for creating API GW in your AWS account. It requires `boto3` but it does not need to be setup for Burp, and you need to have valid AWS profile setup:

```
Usage: createapigws.py [OPTIONS]

Options:
  --profile TEXT     AWS profile to use  [default: pentest1]
  --state-file TEXT  API GW state directory, script creates STATE_FILE and
                     STATE_FILE.json.  [default: api_gateways.txt]
  --create TEXT      specify target URL: https://example.com
  --delete
  --help             Show this message and exit.
```

1. Setup [Jython](https://www.jython.org/download.html) in Burp Suite.
2. Ensure you have a set of AWS keys and profile setup that have full access to the API Gateway service. This is available through the free tier of AWS.
3. Insert state file path from `createapigws.py` to API GW File.
4. Insert the target domain you wish to target.
5. Insert the stage name to Stage name if required.
6. Select HTTPS if the domain is hosted over HTTPS.
7. Click "Enable".
8. Once you are done ensure you click disable.
9. To delete you API GWs use `createapigws.py` script.

### The Burp UI

![Burp Extension UI](ui.png)

### Example of how the requests look

![Sample Requests](example.png)

### Setup

Make sure you have Jython installed and add IPRotate.py through the Burp Extension options.

![Extension Setup](setup.png)

## Previous Research

After releasing this extension it was pointed out that there has been other research in this area using AWS API Gateway to hide an IP address. There is some awesome research and tools by [@ustayready](https://twitter.com/ustayready) [@ryHanson](https://twitter.com/ryHanson) and [@rmikehodges](https://twitter.com/rmikehodges) using this technique.

Be sure to check them out too:

- [fireprox](https://github.com/ustayready/fireprox)
- [hideNsneak](https://github.com/rmikehodges/hideNsneak)
