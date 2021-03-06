# simple-ca

A simple tool to setup a self-signed certificate authority that can issue certificates.

## Concepts
Uses the following concepts
* Root CA
* Intermediatery CA
* Issuing CA

Both Root and Intermediatery have long lifespans. Once an Issuing CA has
been setup, the Root and Intermediatery private keys should be kept on
offline media and only copied back when needing to create another Issuing CA.

There can only be one Root CA but several Intermediatery CAs. Every
Intermediatery CA can have several Issuing CAs bound to it.

The Issuing CA issues ordinary certificates. It has a short lifespan and
thus certificates generated by it inherits that short lifespan. When
generating server certificates it is the passphrase of the Issuing CA's
private key that's asked for when signing the certificate request.

## Naming Conventions

| CA  | Examples | Description |
| --- | -------- | ----------- |
| Root | Root CA, My Root CA | Descriptive text for the Root CA
| Intermediatery | Internal Int CA, External Int CA, Dev Int CA | Several Intermediaterys could be setup for different purposes, such as internal in-house and customer use. A Dev Intermediatery with short lifespan could be setup for a dev project before going into production.
| Issuing | Issuing CA N01, Issuing CA N02 | Since these will have a short lifespan, having a serialnumber as part of the name is a good idea
