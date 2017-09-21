# EZ-SSL
The hassle-free Java toolkit for doing SSL stuff.

## Introduction
Doing SSL things in Java is notoriously complicated, this toolkit tries to make
things easier. It includes a suite of bash scripts which are essentially
wrappers for `keytool` with certain arguments, and two Java classes for SSL
socket server and client.

## Generating key pair with signed certificate
The procedure of generating certificates with EZ-SSL toolkit can be explained
with an example. Assume we want to build a system which requires SSL, and we
want to use our private CA.

### Create the CA
The first thing to do is to create the CA, let's call the CA "Boss".
Obviously, the CA needs a public/private key pair, as well as a certificate
containing its public key, so that others can import the certificate and trust
the CA.

First we create the key pair with:

```gen_ca_key_pair Boss```

After setting the password and other information, we will get a file called
`Boss.jks`, which contains the public/private key pair of Boss. Make sure to
keep this file and the password secured, because this file will represent the
signature power and the identity of Boss.

Then we generate the certificate of Boss with

```export_certificate Boss.jks```

After typing the password of Boss, we will get a file called `Boss.pem`, and
this is the self-signed certificate of Boss, we can share this certificate with
others so that they can trust Boss.

### Request a signed certificate
Now we switch our role to a department called Alpha, and we want to get a
certificate signed by Boss.

First we create out public/private key pair with:

```gen_key_pair Alpha```

After setting the password and other information, we will get a file called
`Alpha.jks`, which contains the public/private key pair of Alpha. Make sure to
keep this file and password secured within Alpha Department, because this file
will represent the identity of Alpha.

Then we need to trust Boss (of course), so that we can trust all certificates
signed by Boss, and we can also request Boss to sign our certificate. So we ask
Boss for its certificate `Boss.pem`, then we trust this certificate with:

```import_certificate Boss.pem Alpha.jks```

Now we can ask Boss to sign our certificate. We generate a Certificate Signature
Request (CSR) with:

```gen_csr Alpha.jks```

Then we will get a file `Alpha.csr`. We can send this file to Boss to request a
signed certificate.

### Sign a certificate
Now switch to Boss. We just received a CSR `Alpha.csr` from Alpha Department,
and we agree to sign it. So we can sign it with:

```sign_certificate Alpha.csr Boss.jks```

We will get a file `Alpha.pem`, which is the certificate of Alpha signed by
Boss. We can send this signed certificate back to Alpha Department.

### Import the signed certificate
Now switch to Alpha. We just received the signed certificate `Alpha.pem` from
Boss, so we just update our key pair with this signed certificate with:

```import_certificate Alpha.pem Alpha.jks```

Now our key pair is good to be used in SSL, if the other side trusts Boss.
