# REST-API-HMAC-Authentication
How to generate a HMAC signature for your REST API request and how to authenticate the received HMAC signature in C# .Net

On the client side use generateHMACSignature() to generate your HMAC signature and add the string to the request's header.

On the server side feed the incoming request into CheckIncomingAPIRequest() to authenticate the user's API request.

How does this all work?

Users will have a generated Public and Private key. The private key will be displayed to the user only one time as it acts as the "password" in this system.

The user will create their HMAC signature using their Public and Private key with other parameters to add to their request's header.

Once the server receives the request it separates the values out from the request header. The Public key is then used to extract the user's Private key from the API database.

With the Received Public key and other parameters from the request and the Private key extracted from the API database. The HMAC signature is recreated on the server side and then compared to the received HMAC signature. If they're a match True is returned, otherwise false.

Rate limiting and IP banning will be added to the code base soon. 


