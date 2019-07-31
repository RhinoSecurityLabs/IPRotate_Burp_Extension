# IPRotator_Burp_Extension
Extension for Burp Suite which uses AWS API Gateway to rotate your IP on every request.

This extension allows you to easily spin up API Gateways across multiple regions. All the Burp Suite traffic for the targeted host is then routed through the API Gateway endpoints which causes the IP to be different on each request. (There is a chance for recycling of IPs but this is pretty low and the more regions you use the less of a chance.)

This is useful to bypass IP blocking defense like bruteforce protection that blocks based on IP, API rate limiting based on IP or WAF blocking based on IP etc.
