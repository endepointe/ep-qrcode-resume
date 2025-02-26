

# Purpose
My goal here is to restrict access to resume (or any data) that needs to remain public. If an authorized user 
is given access to a resource through the correct channel, they will be granted one-time access for that session.

**To accomplish this goal, I will use a qrcode equipped with an authorization challenge url.**

1. User scans a QR code of endepointe.com/b3y0u2sElf?HuMaNc0d3=<encrypted_secret>
2. Their client will navigate to the /b3y0u2sElf?HuMaNc0d3=<encrypted_secret>
3. The server will attempt to decrypt the <encrypted_secret> and issue a token.
4. Client uses session token to access resource at /qr/resume



