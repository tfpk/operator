# Operator

    "Call now! Operator [is] standing by!" ~me, selling you on Operator

## Summary

Operator is designed to solve two problems at once:

 - I want to publish scripts on a cgi server, but only to people with authentication
 - I want to be able to use the results of those scripts elsewhere, while being able to confirm their validity.

If you want to use a private service elsewhere, you could expose it constantly, but then you may get
angry knocks on your door. You could then password protect access to it, but now you have to have
shared keys that might get stolen and that are difficult to revoke. So, you need to use RSA!

That would be enough, but now every time you want to verify some claim, you have to re-use that
service. This might get cubmersome if you're making many calls, so why not just make a single call,
and then sign that call to prove the output was produced by you?

This thought process leads to Operator! We then use the industry standard JWT format to transmit
and sign information, which also makes it perfect for use as a bearer token!

## Internal Structure

In the same directory as the cgi executable, Operator expects to have a folder named `config`
with a directory structure like the following (folders and files that must be named exactly
are marked with `[*]`):

```
config/ [*]
    keys/ [*]
        group/ [*]
            user_name.der
            another_user_name.der
        operator/ [*]
            public.pem [*] # Note: these keys must be provided in PEM format.
            private.pem [*]
    operations/ [*]
        group/ [*]
            hello_world.sh
            secret_script
```

This demonstrates `operator`'s two major concepts: Operations and Groups

### Operations

An Operation is a script that will be run by Operator. It must be executable and should only require
stdin (and print to stdout). This is to prevent attacks that use shell escaping, or exploit stderr.

If you want to run some other program, write a simple wrapper script (it will probably be useful to
filter that program's output anyhow).

### Keys

Keys are used to restrict access to Operations - a user may only perform an operation if they sign
their request with the key that corresponds to a public key in the keys directory.

Public keys for groups must be provided in the DER format.
To convert a normal (PEM) key into a DER key, use the following commands:

```
openssl rsa -in private.pem -outform DER -out private.der
openssl rsa -in private.der -inform DER -RSAPublicKey_out -outform DER -out public.der
```

### Groups

A Group consists both of some number of keys, and operations. If a key exists within a group,
it may run all of the operations within that group.

A key or operation may be in many groups. It is recommended to use symlinks when having
keys or operations in multiple groups


## Endpoints

```
/operator/operation/ [POST]
/operator/public_key/ [GET]
```

This service only exposes two endpoints - an endpoint to allow operations to be performed, and
an endpoint that returns the contents of the public key used to sign all JWTs.

The `operation` endpoint expects to be passed a JWT in its body. The jwt should have header:

```
{
  "typ": "JWT",
  "alg": "RS256"
}
```

(This means the JWT should be signed with an RSA Key.)

It should have a body:

```
{
  "iat": 123456789,    // unix epoch time
  "group": "group",    // see 'groups'
  "user": "group",     // ^
  "operation": "show", // see 'operations'
  "input": "a",        // ^
}
```

## Tests

// TODO: How to run tests

To test this server on a machine without a cgi server, run the commands:

```
cd $PROJECT_ROOT
ln -s target/debug/ cgi-bin
python2 -m CGIHTTPServer
```
