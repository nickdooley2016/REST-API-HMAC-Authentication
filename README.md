# REST-API-HMAC-Authentication
How to generate a HMAC signature for your REST API request + how to authenticate the received HMAC signature in C# .Net

On the client side use generateHMACSignature() to generate your HMAC signature and add the string to the request's header as the parameter "Auth".

On the server side feed the incoming request into CheckIncomingAPIRequest() to authenticate the user's API request.

How does this all work?

Users will have a generated Public and Private key. The private key will be displayed to the user only one time as it acts as the "password" in this system.

The system will generate random base64 Public and Private key strings and store them in an API table in the database. 

The user will only be shown their Private key once, on creation. Their Public key is always available for viewing. 

When the user wants to make an API request they generate a HMAC signature using their Public and Private key a long with other parameters to add to their request's header.

Once the server receives the request it separates the values out from the request header. The Public key is then used to extract the user's Private key from the API database.

With the Received Public key and other parameters from the request and the Private key extracted from the API database. The HMAC signature is recreated on the server side and then compared to the received HMAC signature. If they're a match True is returned, otherwise false.


