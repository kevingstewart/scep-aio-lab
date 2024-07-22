# SCEP All-in-One Testing Lab
A SCEP all-in-one testing lab

### Introduction
SCEP (Simple Certificate Enrollment Protocol) is an *automated* certificate renewal protocol that is primarily used in MDM solutions to allow mobile devices to enroll and/or receive renewed certificates. This "simple" protocol exchange is based on a set of HTTP messages. The SCEP protocol is documented here:

- [SCEP RFC 8894](https://datatracker.ietf.org/doc/html/rfc8894)
- [Cisco SCEP Implementation](https://www.cisco.com/c/en/us/support/docs/security-vpn/public-key-infrastructure-pki/116167-technote-scep-00.html)
- [SecureW2 SCEP Implementation](https://www.securew2.com/blog/simple-certificate-enrollment-protocol-scep-explained)

The purpose of this repository is to demonstrate the inner workings of the SCEP protocol, within a fully self-contained, container-based, client-server SCEP testing lab. No external resources are required to operate this lab.

<br />

----

### Self-Contained Testing Environment
A testing environment is contained within this repository in the form of a Docker Compose file. This ["all-in-one" Docker Compose](https://github.com/kevingstewart/acme-aio-lab/blob/main/acme-aio-internal-compose.yaml) creates the following services needed to build an SCEP testing lab:

- SCEP server (Ubuntu:22.04)
- SCEP client (Ubuntu:22.04)

The compose file builds two networks - one "internal" used between the two containers, and one "external" for some services to expose ports outside the environment as needed.

The environment is configured as such:
- The entire internal network sits on a 10.10.0.0/16 subnet.
- The SCEP server listens on 10.10.0.10.
- The SCEP client listens on 10.10.0.20.

<br />

----

### Testing SCEP in the All-in-One Lab Environment
The SCEP all-in-one lab consists of a Docker Compose file that builds all of the necessary components to support a fully-contained, container-based environment. No external services are required. 

**To test SCEP**:

1. Start the Docker Compose environment.
   ```shell
   docker compose -f scep-aio-internal-compose.yaml up -d
   ```
2. Tail the SCEP server container log until the logs settles. Many things are happening under the hood. Keep this tail open for the remainder of testing to watch the server-side logs.
   ```shell
   docker logs -f scepserver
   ```
3. Shell into the SCEP client container.
   ```shell
   docker exec -it scepclient /bin/bash
   ```
4. Move to the /scep/client folder in the SCEP client container and issue the following command to generate a new private key, and retrieve a signed certificate from the SCEP server.
   ```
   scepclient -server-url http://10.10.0.10:8080/scep -challenge=secret -private-key client.key \
   -cn "www.f5labs.local" \
   -dnsname "www.f5labs.local" \
   -organization "f5labs.local" \
   -ou "scep.f5labs.local" \
   -locality "Omaha" \
   -province "NE" \
   -country "US"
   ```
5. View the properties of the new signed (server) certificate.
   ```
   openssl x509 -noout -text -in client.pem
   ```
6. Optionally, shut down the Docker Compose when you are done testing. This will reset all configuration data.
   ```shell
   docker compose -f scep-aio-internal-compose.yaml down
   ```



