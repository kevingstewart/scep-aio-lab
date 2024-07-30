# SCEP All-in-One Testing Lab
A SCEP all-in-one testing lab

## Introduction
SCEP (Simple Certificate Enrollment Protocol) is an *automated* certificate renewal protocol that is primarily used in MDM solutions to allow mobile devices to enroll and/or receive renewed certificates. This "simple" protocol exchange is based on a set of HTTP messages. The SCEP protocol is documented here:

- [SCEP RFC 8894](https://datatracker.ietf.org/doc/html/rfc8894)
- [SCEP MicroMDM client/server project](https://github.com/micromdm/scep)
- [Cisco SCEP Implementation](https://www.cisco.com/c/en/us/support/docs/security-vpn/public-key-infrastructure-pki/116167-technote-scep-00.html)
- [SecureW2 SCEP Implementation](https://www.securew2.com/blog/simple-certificate-enrollment-protocol-scep-explained)
- [Blog: Cracking Open SCEP](https://articles.foletta.org/post/2024-07-01-cracking-open-scep/)

The purpose of this repository is to demonstrate the inner workings of the SCEP protocol, within a fully self-contained, container-based, client-server SCEP testing lab. No external resources are required to operate this lab. The repository contains:

- A self-contained Docker Compose environment that defines 3 SCEP servers and 2 SCEP clients. There is also a remote SCEP server that can be tested.
- A set of Wireshark captures for eacg client-server interaction.

<br />

----

## Self-Contained Testing Environment
A testing environment is contained within this repository in the form of a Docker Compose file. This ["all-in-one" Docker Compose](https://github.com/kevingstewart/scep-aio-lab/blob/main/scep-aio-internal-compose.yaml) creates the following services needed to build an SCEP testing lab:

- SCEP servers
   - Smallstep Step-CA Scep [ref](https://hub.docker.com/r/smallstep/step-ca)
   - OpenXPKI Scepserver [ref](https://hub.docker.com/r/larskanis/openxpki/)
   - MicroMDM Scepserver [ref](https://github.com/micromdm/scep/blob/main/README.md)
- SCEP clients
   - MicroMDM Scepclient [ref](https://github.com/micromdm/scep/blob/main/README.md)
   - Certnanny Sscepclient [ref](https://github.com/certnanny/sscep/blob/master/README.md)

The compose file builds an "internal" network used between the containers:

- The entire internal network sits on a 10.10.0.0/16 subnet
- The MicroMDM SCEP server listens on 10.10.0.10
- The OpenXPKI SCEP server listens on 10.10.0.11
- The Smallstep SCEP server listens on 10.10.0.14
- The MicroMDM SCEP client listens on 10.10.0.20
- The Certnanny SSCEP Client listens on 10.10.0.21

<br />

----

## Testing SCEP in the All-in-One Lab Environment
The SCEP all-in-one lab consists of a Docker Compose file that builds all of the necessary components to support a fully-contained, container-based environment. No external services are required. 

**To test SCEP**:

1. Start the Docker Compose environment
   ```shell
   docker compose -f scep-aio-internal-compose.yaml up -d
   ```

2. Tail the SCEP client container log until the logs settles
   ```shell
   docker logs -f scepclient
   ```

3. Shell into the SCEP client container to test 3 different SCEP servers (2 local and 1 remote)

   Note that the MicroMDM SCEP client will perform all of the SCEP negotiations in a single command (i.e., GetCACert, GetCACaps, and PKIOperation).
   ```shell
   docker exec -it scepclient /bin/bash

   ## Change to the /scep folder
   cd /scep

   ## Test against the local MicroMDM SCEP server
   mkdir test_micromdm && cd test_micromdm
   scepclient -server-url http://10.10.0.10:8080/scep -challenge=secret -private-key client.key \
   -cn "www.f5labs.local" \
   -dnsname "www.f5labs.local" \
   -organization "f5labs.local" \
   -ou "scep.f5labs.local" \
   -locality "Omaha" \
   -province "NE" \
   -country "US"
   -debug

   ## Test against the local Smallstep Step-CA SCEP server
   cd ..
   mkdir test_smallstep && cd test_smallstep
   scepclient -server-url http://10.10.0.14:9001/scep/scepca -challenge=secret -private-key client.key \
   -cn "www.f5labs.local" \
   -dnsname "www.f5labs.local" \
   -organization "f5labs.local" \
   -ou "scep.f5labs.local" \
   -locality "Omaha" \
   -province "NE" \
   -country "US" \
   -debug

   ## Test against a remote SCEP server (interop.redwax.eu)
   cd ..
   mkdir test_redwax && cd test_redwax
   scepclient -server-url http://interop.redwax.eu/test/simple/scep -challenge=challenge-password -private-key client.key \
   -cn "www.f5labs.local" \
   -dnsname "www.f5labs.local" \
   -organization "f5labs.local" \
   -ou "scep.f5labs.local" \
   -locality "Omaha" \
   -province "NE" \
   -country "US"
   -debug
   ```
   
5. Shell into the SSCEP client container to test 3 different SCEP servers (2 local and 1 remote)

   Note that the SSCEP client requires each SCEP negotiation to happen separately. It starts with a 'getca' command to get the SCEP server's CA cert. The 'mkrequest' command generates the local private key, initial self-signed certificate, and the CSR with the challenge password and SAN values embedded. The 'enroll' command issues the PKIOperation request passing in all of these files.
   ```shell
   docker exec -it sscepclient /bin/bash

   ## Change to the /scep folder
   cd /scep
   
   ## Test against the local OpenXPKI SCEP server
   mkdir test_openxpki && cd test_openxpki
   sscep getca -u http://10.10.0.11/scep -c ca.crt
   mkrequest -dns www.f5labs.local SecretChallenge
   sscep enroll -u http://10.10.0.11/scep -c ca.crt-0 -k local.key -r local.csr -l local.crt -E 3des -S sha256

   ## Test against the local smallstep SCEP server
   cd ..
   mkdir test_smallstep && cd test_smallstep
   sscep getca -u http://10.10.0.14:9001/scep/scepca -c ca.crt
   mkrequest -dns www.f5labs.local secret
   sscep enroll -u http://10.10.0.14:9001/scep/scepca -c ca.crt-0 -k local.key -r local.csr -l local.crt -E 3des -S sha256

   ## Test against the remote SCEP server (interop.redwax.eu)
   cd ..
   mkdir test_redwax && cd test_redwax
   sscep getca -u http://interop.redwax.eu/test/simple/scep -c ca.crt
   mkrequest -dns www.f5labs.local challenge-password
   sscep enroll -u http://interop.redwax.eu/test/simple/scep -c ca.crt-1 -k local.key -r local.csr -l local.crt -E 3des -S sha256
   ```   

7. View the properties of any of the new signed (server) certificates
   ```
   openssl x509 -noout -text -in client.pem
   ```
   
8. Optionally, shut down the Docker Compose when you are done testing. This will reset all configuration data.
   ```shell
   docker compose -f scep-aio-internal-compose.yaml down
   ```

<br />

----

## SCEP Protocol Deep Dive
The following describes the general inner workings of the SCEP protocol. At a minimum, a client will issue 3 different requests to a SCEP server in the process of requesting a certificate. Note of course there could be variations in this process, depending on client/server implementations and other factors.

### Fetch the CA certificate
Before doing anything the client needs a copy of the CA certificate. This certificate will be used in a later message.

```GET ?operation=GetCACert```

**The response**:
- Content-Type: application/x-x509-ca-cert (or application/x-x509-ca-ra-cert)
- Data: [DER-formatted CA certificate]

  ```openssl x509 -noout -text -inform DER -in scep-ca-cert.crt```


### Fetch the CA's capabilities
The client now makes a request to get the SCEP server's capabilities. This informs the client of both the supported operations and encryption types available. Notably, if 'POSTPKIOperation' is returned, the subsequent enrollment request should be a POST. Otherwise it's a GET request.

```GET ?operation=GetCACaps```

**The response**:
- Content-Type: text/plain
- Data: [text list of capabilities]
  <details>
     <summary>Example SCEP capabilities</summary>
     
     ```
     Renewal
     SHA-1
     SHA-224
     SHA-256
     SHA-384
     SHA-512
     AES
     DES3
     SCEPStandard
     GetNextCACert
     POSTPKIOperation
     ```
     
  </details>


### Request a certificate
The client will now send its certificate request. It can either be in a POST request with Content-Type ```application/octet-stream```, or as a GET request with the value in a ```message``` query parameter, base64-encoded, and then URI-encoded. The raw data is in CMS (Cryptographic Message Syntax), as defined in RFC5652, which provides a way to digitally sign, digest, authenticate, or encrypt arbitrary message content. 

```POST ?operation=PKIOperation```

**The request**:
- The client must possess or create a private key. From that key the client will now also generate a temporary self-signed certificate containing a public key. This self-signed certificate allows the SCEP server to authenticate the data that been transferred. The view this raw CMS data:

   ```openssl cms -cmsout -inform DER -print -in scep-signing-req.cms```
   
   <details>
      <summary>Example request CMS data</summary>

      CMS_ContentInfo: 
        contentType: pkcs7-signedData (1.2.840.113549.1.7.2)
        d.signedData: 
          version: 1
          digestAlgorithms:
              algorithm: sha1 (1.3.14.3.2.26)
              parameter: <ABSENT>
          encapContentInfo: 
            eContentType: pkcs7-data (1.2.840.113549.1.7.1)
            eContent: 
              ...redacted...
          certificates:
            d.certificate: 
              cert_info: 
                version: 2
                serialNumber: 41917794373341774717824986598557650123
                signature: 
                  algorithm: sha256WithRSAEncryption (1.2.840.113549.1.1.11)
                  parameter: NULL
                issuer: O=f5labs.local, CN=SCEP SIGNER
                validity: 
                  notBefore: Jul 23 14:48:00 2024 GMT
                  notAfter: Jul 23 15:48:00 2024 GMT
                subject: O=f5labs.local, CN=SCEP SIGNER
                key: 
                  algor: 
                    algorithm: rsaEncryption (1.2.840.113549.1.1.1)
                    parameter: NULL
                  public_key:  (0 unused bits)
                    ...redacted...
                issuerUID: <ABSENT>
                subjectUID: <ABSENT>
                extensions:
                    object: X509v3 Key Usage (2.5.29.15)
                    critical: TRUE
                    value: 
                      0000 - 03 02 05 a0                              ....
      
                    object: X509v3 Extended Key Usage (2.5.29.37)
                    critical: BOOL ABSENT
                    value: 
                      0000 - 30 0a 06 08 2b 06 01 05-05 07 03 01      0...+.......
      
                    object: X509v3 Basic Constraints (2.5.29.19)
                    critical: TRUE
                    value: 
                      0000 - 30                                       0
                      0002 - <SPACES/NULS>
              sig_alg: 
                algorithm: sha256WithRSAEncryption (1.2.840.113549.1.1.11)
                parameter: NULL
              signature:  (0 unused bits)
                ...redacted...
          crls:
            <EMPTY>
          signerInfos:
              version: 1
              d.issuerAndSerialNumber: 
                issuer: O=f5labs.local, CN=SCEP SIGNER
                serialNumber: 41917794373341774717824986598557650123
              digestAlgorithm: 
                algorithm: sha1 (1.3.14.3.2.26)
                parameter: <ABSENT>
              signedAttrs:
                  object: undefined (2.16.840.1.113733.1.9.2)
                  value.set:
                    PRINTABLESTRING:19
      
                  object: contentType (1.2.840.113549.1.9.3)
                  value.set:
                    OBJECT:pkcs7-data (1.2.840.113549.1.7.1)
      
                  object: signingTime (1.2.840.113549.1.9.5)
                  value.set:
                    UTCTIME:Jul 23 14:48:00 2024 GMT
      
                  object: undefined (2.16.840.1.113733.1.9.5)
                  value.set:
                    OCTET STRING:
                      0000 - 32 75 57 ff a9 5e 99 01-9f 7a 5d ee 84   2uW..^...z]..
                      000d - 46 58 c9                                 FX.
      
                  object: messageDigest (1.2.840.113549.1.9.4)
                  value.set:
                    OCTET STRING:
                      0000 - 01 61 c6 93 75 9f be f2-b3 77 1a fa 6c   .a..u....w..l
                      000d - 12 3d f5 37 a2 1c 96                     .=.7...
      
                  object: undefined (2.16.840.1.113733.1.9.7)
                  value.set:
                    PRINTABLESTRING:Hy2AMoE4g1kBt8r8vPHfs8XqxkE=
              signatureAlgorithm: 
                algorithm: sha1WithRSAEncryption (1.2.840.113549.1.1.5)
                parameter: <ABSENT>
              signature: 
                ...redacted...
              unsignedAttrs:
                <EMPTY>
   </details>

   There are multiple layers of data in this object. Most important, the self-signed certificate is in the *certificates* block. To extract and view this self-signed certificate:

   ```
   openssl cms -verify -in scep-signing-req.cms -inform DER -signer self_signed.cer -noverify -out /dev/null
   openssl x509 -in self_signed.cer -noout -text
   ```

   <details>
      <summary>Example self-signed certificate</summary>

      Certificate:
       Data:
           Version: 3 (0x2)
           Serial Number:
               1f:89:12:d3:6d:74:b4:bf:f9:39:58:8d:a7:50:8c:cb
       Signature Algorithm: sha256WithRSAEncryption
           Issuer: O=f5labs.local, CN=SCEP SIGNER
           Validity
               Not Before: Jul 23 14:48:00 2024 GMT
               Not After : Jul 23 15:48:00 2024 GMT
           Subject: O=f5labs.local, CN=SCEP SIGNER
           Subject Public Key Info:
               Public Key Algorithm: rsaEncryption
                   RSA Public-Key: (2048 bit)
                   Modulus:
                       00:da:09:b4:b6:b3:02:e8:bb:aa:e3:dc:89:86:1c:
                       41:42:23:c5:33:e0:fa:15:b9:2c:5c:91:07:94:b8:
                       aa:ba:10:c8:24:83:ac:fa:f0:68:34:39:92:a7:a6:
                       a2:86:8d:58:b1:37:7b:53:6d:46:0d:6e:75:a9:8b:
                       4c:ad:f8:94:f6:f3:7e:3d:6d:eb:b2:db:fd:8d:fb:
                       85:97:9a:b0:a0:46:11:9f:3d:de:d5:92:a2:ac:58:
                       b2:85:16:48:21:9a:0d:eb:7f:0d:27:0e:32:92:be:
                       01:85:4d:c2:1f:d7:0b:41:e3:e3:34:86:04:08:0e:
                       98:83:92:27:bb:85:66:89:43:28:25:6b:02:e2:0c:
                       88:b7:6e:da:de:87:57:7c:f9:e9:a4:b4:87:c5:8f:
                       d8:14:3a:c1:a2:18:d6:18:e8:42:03:91:99:42:44:
                       92:51:b8:32:4f:5d:d3:b4:a7:ec:12:a9:8a:50:a8:
                       0d:fd:bb:da:91:e6:7b:9d:ee:62:3f:3e:9c:b2:b1:
                       87:52:61:fc:94:b4:33:b3:55:a5:02:dc:8a:66:2b:
                       33:e1:09:6a:2a:c5:1f:d9:83:55:64:4d:d7:d3:38:
                       67:19:32:f4:c6:78:8e:a3:5d:b3:26:c6:3d:a4:5a:
                       bd:42:1d:9a:ae:6c:11:f4:82:6e:89:59:86:a6:e2:
                       99:09
                   Exponent: 65537 (0x10001)
           X509v3 extensions:
               X509v3 Key Usage: critical
                   Digital Signature, Key Encipherment
               X509v3 Extended Key Usage: 
                   TLS Web Server Authentication
               X509v3 Basic Constraints: critical
                   CA:FALSE
       Signature Algorithm: sha256WithRSAEncryption
            30:da:b8:99:d4:b4:f6:0c:97:11:0e:3d:43:70:3d:e0:80:3c:
            71:58:4b:92:3d:61:7e:66:fe:43:d2:cf:4c:6f:42:ba:0b:7d:
            60:5e:df:fb:88:1a:74:43:1c:8c:d9:e5:b0:f4:4e:30:08:49:
            68:c5:ed:e8:20:d2:f0:14:09:7d:b9:ac:9c:83:cd:04:6a:e4:
            a4:72:01:db:83:42:3a:52:e6:3e:f2:02:2c:ea:17:b3:26:3d:
            20:91:33:89:23:fe:d9:15:55:dd:36:fc:ad:ba:54:9b:76:cc:
            11:1d:0c:2b:24:af:1d:d2:21:19:00:86:a5:21:0f:22:31:66:
            5f:fd:fd:52:68:9c:fa:4f:1a:e7:28:f5:eb:67:12:ff:f0:45:
            5e:bb:98:66:0a:d5:1b:10:d6:1f:d8:78:60:9a:10:9f:7a:41:
            f8:e8:fb:80:22:56:bb:d3:7a:7d:07:3c:d7:43:f4:22:92:7a:
            d9:5a:70:62:52:46:8f:af:e1:6a:42:23:96:eb:cb:50:86:ff:
            88:a3:be:6b:5a:49:2b:9f:b1:46:49:00:35:b3:c2:be:8a:b8:
            e0:7b:55:ce:86:59:94:23:37:78:b1:8a:81:5f:57:84:83:32:
            8d:52:dc:59:31:39:8f:2c:be:35:c7:5b:ca:03:57:95:6c:ee:
            d7:9b:af:3c
  </details>

  Also equally important is the eContentType (pkcs7-data) blob, which is another CMS encapsulation containing the certificate request. The CA certificate and key can be used to decrypt this second CMS object to expose the Certificate Signing Request (CSR) data. This will be a fairly standard CSR with an additional **challengePassword** attribute containing the SCEP server's challenge password. Notably, encapsulation of the CSR is done by encrypting with the CA's public key, received in the GetCACert request. The CA can then use its private key to extract the CSR data.

  ```
  openssl cms -in scep-signing-req.cms -verify -inform DER -noverify | openssl cms -inform DER -decrypt -recip ca.pem -inkey ca.key | openssl req -inform DER -noout -text
  ```

  <details>
     <summary>Example certificate signing request</summary>

     ```
     Certificate Request:
       Data:
           Version: 0 (0x0)
           Subject: C=US, ST=NE, L=Omaha, O=f5labs.local, OU=scep.f5labs.local, CN=www.f5labs.local
           Subject Public Key Info:
               Public Key Algorithm: rsaEncryption
                   RSA Public-Key: (2048 bit)
                   Modulus:
                       00:da:09:b4:b6:b3:02:e8:bb:aa:e3:dc:89:86:1c:
                       41:42:23:c5:33:e0:fa:15:b9:2c:5c:91:07:94:b8:
                       aa:ba:10:c8:24:83:ac:fa:f0:68:34:39:92:a7:a6:
                       a2:86:8d:58:b1:37:7b:53:6d:46:0d:6e:75:a9:8b:
                       4c:ad:f8:94:f6:f3:7e:3d:6d:eb:b2:db:fd:8d:fb:
                       85:97:9a:b0:a0:46:11:9f:3d:de:d5:92:a2:ac:58:
                       b2:85:16:48:21:9a:0d:eb:7f:0d:27:0e:32:92:be:
                       01:85:4d:c2:1f:d7:0b:41:e3:e3:34:86:04:08:0e:
                       98:83:92:27:bb:85:66:89:43:28:25:6b:02:e2:0c:
                       88:b7:6e:da:de:87:57:7c:f9:e9:a4:b4:87:c5:8f:
                       d8:14:3a:c1:a2:18:d6:18:e8:42:03:91:99:42:44:
                       92:51:b8:32:4f:5d:d3:b4:a7:ec:12:a9:8a:50:a8:
                       0d:fd:bb:da:91:e6:7b:9d:ee:62:3f:3e:9c:b2:b1:
                       87:52:61:fc:94:b4:33:b3:55:a5:02:dc:8a:66:2b:
                       33:e1:09:6a:2a:c5:1f:d9:83:55:64:4d:d7:d3:38:
                       67:19:32:f4:c6:78:8e:a3:5d:b3:26:c6:3d:a4:5a:
                       bd:42:1d:9a:ae:6c:11:f4:82:6e:89:59:86:a6:e2:
                       99:09
                   Exponent: 65537 (0x10001)
           Attributes:
               challengePassword        :secret
           Requested Extensions:
               X509v3 Subject Alternative Name: 
                   DNS:www.f5labs.local
       Signature Algorithm: sha256WithRSAEncryption
            d2:27:61:e7:cc:46:13:56:99:be:3c:46:5d:5c:a3:ff:93:a1:
            44:ab:7f:92:4f:56:39:27:20:e5:1f:80:0c:60:d9:c7:5a:c9:
            54:1e:38:c6:54:01:23:2b:8a:4a:d5:1c:b6:88:7e:6c:c1:aa:
            38:65:c0:42:49:9a:6a:29:16:3f:22:0f:6d:3d:c8:37:67:83:
            1f:83:f6:14:05:1b:6d:50:ff:97:48:22:23:f1:12:91:7a:f3:
            5c:92:a5:66:3b:c7:37:51:89:43:ed:fe:bd:26:6a:ab:30:fa:
            86:7a:10:c2:31:03:76:ba:1c:c8:04:5a:85:9f:4d:3b:9f:5b:
            77:24:b4:b4:8d:79:19:3b:77:ee:e5:c1:39:f7:79:9c:e0:62:
            c3:94:14:09:47:56:74:48:c2:55:86:cc:f1:79:1c:a5:85:47:
            90:3b:3e:7a:80:64:ad:ed:c9:e7:49:13:b2:42:c7:1e:3e:d6:
            56:8f:25:cd:78:d8:cf:da:de:65:bc:c6:0c:84:1c:ac:6a:e7:
            04:dd:31:e7:ae:ad:cd:cf:00:59:6a:9b:c1:d6:ca:68:47:81:
            2d:52:7b:07:79:c0:98:42:83:97:fb:71:76:12:38:5d:70:fe:
            c3:79:66:42:a7:ec:39:5b:49:2f:ae:77:d2:60:4a:2a:aa:68:
            95:f3:2d:f0
     ```

**The response**:
Assuming the SCEP server can correctly validate the client's request, its subsequent response should be the signed certificate.
- Content-Type: application/x-pki-message
- Data: the data returned will also be a CMS object, containing two values:
  - A *verification* CMS, signed using the public key in the cert request, allowing the client to verify it with the generated private key
  - An *encrypted* CMS with a key encrypted by the self-signed cert that was sent in the request, allowing the client to decrypt using its generated private key

    The signed certificate can be extracted from this CMS data by decrypting with the self-signed certificate and the original private key

    ```
    openssl cms -verify -in scep-signed-resp.cms -inform DER -noverify | openssl cms -decrypt -inform der -recip self_signed.cer -inkey client.key | openssl pkcs7 -inform der -noout -print_certs -text
    ```

    <details>
       <summary>Example signed certificate</summary>

       ```
       Certificate:
          Data:
              Version: 3 (0x2)
              Serial Number: 2 (0x2)
          Signature Algorithm: sha256WithRSAEncryption
              Issuer: C=US, O=scep-ca, OU=SCEP CA, CN=MICROMDM SCEP CA
              Validity
                  Not Before: Jul 23 14:38:00 2024 GMT
                  Not After : Jul 23 14:48:00 2025 GMT
              Subject: C=US, ST=NE, L=Omaha, O=f5labs.local, OU=scep.f5labs.local, CN=www.f5labs.local
              Subject Public Key Info:
                  Public Key Algorithm: rsaEncryption
                      RSA Public-Key: (2048 bit)
                      Modulus:
                          00:da:09:b4:b6:b3:02:e8:bb:aa:e3:dc:89:86:1c:
                          41:42:23:c5:33:e0:fa:15:b9:2c:5c:91:07:94:b8:
                          aa:ba:10:c8:24:83:ac:fa:f0:68:34:39:92:a7:a6:
                          a2:86:8d:58:b1:37:7b:53:6d:46:0d:6e:75:a9:8b:
                          4c:ad:f8:94:f6:f3:7e:3d:6d:eb:b2:db:fd:8d:fb:
                          85:97:9a:b0:a0:46:11:9f:3d:de:d5:92:a2:ac:58:
                          b2:85:16:48:21:9a:0d:eb:7f:0d:27:0e:32:92:be:
                          01:85:4d:c2:1f:d7:0b:41:e3:e3:34:86:04:08:0e:
                          98:83:92:27:bb:85:66:89:43:28:25:6b:02:e2:0c:
                          88:b7:6e:da:de:87:57:7c:f9:e9:a4:b4:87:c5:8f:
                          d8:14:3a:c1:a2:18:d6:18:e8:42:03:91:99:42:44:
                          92:51:b8:32:4f:5d:d3:b4:a7:ec:12:a9:8a:50:a8:
                          0d:fd:bb:da:91:e6:7b:9d:ee:62:3f:3e:9c:b2:b1:
                          87:52:61:fc:94:b4:33:b3:55:a5:02:dc:8a:66:2b:
                          33:e1:09:6a:2a:c5:1f:d9:83:55:64:4d:d7:d3:38:
                          67:19:32:f4:c6:78:8e:a3:5d:b3:26:c6:3d:a4:5a:
                          bd:42:1d:9a:ae:6c:11:f4:82:6e:89:59:86:a6:e2:
                          99:09
                      Exponent: 65537 (0x10001)
              X509v3 extensions:
                  X509v3 Key Usage: critical
                      Digital Signature, Key Encipherment, Data Encipherment
                  X509v3 Extended Key Usage: 
                      TLS Web Client Authentication, TLS Web Server Authentication
                  X509v3 Subject Key Identifier: 
                      1F:2D:80:32:81:38:83:59:01:B7:CA:FC:BC:F1:DF:B3:C5:EA:C6:41
                  X509v3 Authority Key Identifier: 
                      keyid:C9:69:16:F9:B9:29:F1:B3:57:4D:74:BE:08:F6:CE:25:74:24:32:AC
      
                  X509v3 Subject Alternative Name: 
                      DNS:www.f5labs.local
          Signature Algorithm: sha256WithRSAEncryption
               a8:9c:a1:83:16:80:4d:e0:6f:f2:b4:89:29:29:64:cc:36:cc:
               41:c2:b6:4b:15:e3:12:f5:a2:85:6c:8c:2a:b6:59:86:2e:53:
               b8:09:43:06:81:47:7a:aa:36:d0:8c:05:ba:c0:e6:81:ed:62:
               27:42:ee:3d:9f:b8:30:b5:b4:60:69:d6:5a:a3:98:bf:4b:1d:
               e2:98:b2:68:21:59:33:e2:c5:bc:70:1b:86:9e:55:c2:61:91:
               15:43:49:c9:fc:0f:f8:73:e9:4b:1e:01:a4:56:35:92:7a:5c:
               ed:46:68:f7:c4:ca:54:a5:bc:be:85:e0:0e:32:51:3a:24:b9:
               89:e5:57:39:c4:8c:dc:a5:ab:ba:aa:e6:3a:42:05:5e:5d:d1:
               20:63:bd:fb:23:19:3a:9e:94:e2:77:f8:b7:8d:10:ed:af:88:
               d9:db:93:a6:fa:4d:b3:97:b6:ad:60:fd:b6:8c:0c:c6:f6:5d:
               1e:3f:dc:92:c1:8b:9f:6b:e2:c1:b4:8a:ff:82:24:05:f4:87:
               02:be:6d:0a:66:71:c7:80:47:fb:6c:cf:21:31:ed:6a:e4:2e:
               19:8b:43:d4:04:5c:0d:ca:f3:b2:ef:12:b3:3c:ad:db:40:44:
               e6:e9:8c:22:ce:66:2e:0a:d8:df:69:09:1a:7b:11:48:42:1f:
               cf:dd:64:73:f1:68:15:81:87:d5:4a:15:00:97:e8:1e:46:ef:
               c7:2c:ac:a7:11:42:c8:74:58:8d:54:95:50:32:6e:3a:6e:c8:
               59:2a:48:1a:4b:27:36:9e:ac:ba:e4:e3:b4:32:91:7e:d3:82:
               84:6b:15:e8:66:64:8a:21:5e:df:d8:b3:82:fe:7e:50:ef:74:
               0c:ba:82:6b:64:0c:6b:fc:2f:8e:eb:aa:c7:86:38:82:eb:70:
               2c:7e:fc:b9:0e:72:f7:ab:ff:ca:a9:27:33:4c:c9:ce:42:46:
               28:04:e2:bb:48:3f:a1:65:ed:a1:e0:a6:42:3d:c5:7b:f1:f9:
               fc:dd:d9:77:28:f9:06:41:a5:3d:1c:44:8a:8e:48:a9:79:0a:
               56:b0:79:12:a5:c2:43:a0:b9:09:19:9a:73:43:86:f4:80:c7:
               c7:4b:a1:90:85:36:89:eb:58:10:c5:d1:f7:02:00:9f:00:07:
               b1:eb:7e:10:6b:b8:95:c2:a6:80:b3:40:29:ff:88:af:a6:7f:
               9d:44:66:1a:c1:c0:9e:0f:71:04:ba:f7:2c:d3:5c:21:9f:5d:
               09:69:b3:ee:a3:a0:c0:19:64:44:36:39:6a:8c:c3:d7:ea:84:
               d7:b4:6d:15:ed:4e:2c:46:78:91:2f:c6:b0:82:5e:98:79:16:
               6b:d6:84:64:43:d4:ab:bb
       ```
    </details>

    At this point, the client can move the new signed certificate into the proper location to handle TLS transactions.













