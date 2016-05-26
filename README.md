# Firebase Token Generator - Python

[Firebase Custom Authentication](https://firebase.google.com/docs/auth/server#create_a_custom_token)
gives you complete control over user authentication by allowing you to authenticate users
with secure JSON Web Tokens (JWTs). The auth payload stored in those tokens is available
for use in your Firebase [security rules](https://www.firebase.com/docs/security/api/rule/).
This is a token generator library for Python which allows you to easily create those JWTs.


## Installation

The Firebase Python token generator library is available via pip:

```bash
$ pip install firebase-token-generator
```

## A Note About Security

**IMPORTANT:** Because token generation requires a service account and its private key, you should only generate
tokens on *trusted servers*. Never embed your Firebase service account credentials directly into your application and
never share your credentials with a connected client.


## Generating Tokens

To generate tokens, you'll need to create a service account for your Firebase project using [IAM Admin - Service Accounts(https://console.firebase.google.com/iam-admin/serviceaccounts/). Create a service account and download its private key in JSON format.

Once you've downloaded the library and grabbed your credentials JSON, you can generate a token with
this snippet of Python code:

```python
from firebase_token_generator import create_token

# "private_key" in the credentials JSON
private_key = "..."
# "client_email" in the credentials JSON
service_account_email = "..." 

auth_payload = {"auth_data": "foo", "other_auth_data": "bar"}
token = create_token(service_account_email, private_key, "user1", auth_payload)

# A client SDK can use the resulting token to authenticate user "user1".
```

The payload passed to `create_token()` is made available for use within your
security rules via the [`auth` variable](https://firebase.google.com/docs/database/security/user-security#section-variable). This is how you pass trusted extra authentication details, e.g. a premium account status.


## Token Options

Unlike earlier versions of firebase-token-generator, the internal claims of the token - most notably, expiration and administrator access - are no longer configurable. An authentication token expires in 60 minutes.
