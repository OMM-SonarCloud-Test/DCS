# DCS Crypto Service Container

The DCS Crypto Service Container provides a self-contained DCS Crypto Service offering data-level cryptography.  DCS, including the Crypto Service Container is available under the Apache 2.0 software license, but this container is based on the Red Hat Enterprise Linux (RHEL) 9 Universal Basic Image (UBI), which is subject to their licensing terms.  See https://www.redhat.com/en/about/red-hat-end-user-license-agreements#UBI for specifics about the RHEL 9 UBI licensing.

## Building the Container

Follow the instructions in the root level README.md to configure and build DCS.  In particular, make sure to configure the CONTAINER_EXEC variable in setenv.sh to match your local container engine. CONTAINER_EXEC defaults to /bin/podman, since that is the default container virtualzation package offered on Red Hat Enterprise Linux 9.  Once the build is complete, use the deploy.sh script to execute the container builds.

From the root of the DCS repository, run the following command once the build and tests are complete:
```kmc-resources/scripts/deploy.sh --img```

That command will deploy all of the DCS files into a local directory (kmc-resources/packaging/container/kmcroot) and then execute the container build process using the Dockerfile in each of the service container trees.  The container build process requires access to the Internet for two things: 
* Retrieval of the RHEL9 UBI image
* Download of the BouncyCastle FIPS Java library from Maven Central, which is used to support FIPS-compliant keystores.

At the end of the container build process, there should be three DCS containers in your local image repository (examples shown using podman):

```
$ podman image ls
REPOSITORY                                  TAG         IMAGE ID      CREATED            SIZE
localhost/kmc-sa-mgmt-service               4.0.0       aebf0191473b  About an hour ago  890 MB
localhost/kmc-sdls-service                  4.0.0       cfb068d65d92  About an hour ago  890 MB
localhost/kmc-crypto-service                4.0.0       2e1285394471  About an hour ago  890 MB
```

The image can be saved to transferrable image files with the following commands:
```
$ podman image save -o kmc-crypto-service-4.0.0.tar kmc-crypto-service:4.0.0
```

## Crypto Service Container Configuration Options
There are a large number of configurable options that control the behavior and operation of the DCS Crypto Service Container.  The full list is documented here.

Some of the configuration options are "sensitive" data -- TLS keys, keystores, passwords, etc.  It is *STRONGLY RECOMMENDED* that secure methods be used to provide these configuration items to the container.  Podman/docker secrets, Amazon Secrets Manager, and similar systems can and should be used for any configuration options marked "Sensitive."  


## Deploying the Crypto Service Container

The DCS Crypto Service Container can be deployed via a wide variety of tools and processes.  Examples are provided for running the bare container with podman and using podman-compose.  Releases of the Crypto Service Container are also tested in the Amazon Elastic Container Service (ECS), and can be run there.  The DCS Crypto Service Container should be deployable on any container virtualization system that supports OCI-compliant images and processes.

There are a large number of configurable options that control the behavior and operation of the DCS Crypto Service Container.  For the full list, see "Crypto Service Container Configuration Options" above. These examples are minimalist configurations that utilize the default settings as much as possible.  

Both examples below use podman secrets for sensitive configuration information, as well as for a simple method to provide some non-sensitive options (like the TLS CA Certificate Bundle).

### Deploying with Podman

1. Import the Image (optional, if image is available in a configured repository)
```bash
$ podman image load -i kmc-crypto-service-4.0.0.tar.gz
```

1. Configure Secrets
```bash
$ podman secret create tls_host_key /etc/pki/tls/private/ammos-server-key.pem
$ podman secret create tls_host_cert /etc/pki/tls/certs/ammos-server-cert.pem
$ podman secret create tls_ca_bundle /etc/pki/tls/certs/ammos-ca-bundle.crt
$ podman secret create crypto_keystore /msn_data/crypto/crypto_keystore.bcfks
$ podman secret create tls_mtls_truststore /etc/pki/tls/private/ammos-mtls-truststore.jks
$ echo "changeit" | podman secret create tls_mtls_truststore_pass -
$ echo "s00p3rs3cr3tp@ssph4se" | podman secret create crypto_keystore_pass -
```

1. Create DCS Crypto Service Container
```bash
podman container create -p 8443:8443 --name kmc-crypto-service \
  --secret tls_host_key --secret tls_host_cert --secret tls_ca_bundle \
  --secret crypto_keystore --secret crypto_keystore_pass \
  --secret crypto_key_pass --secret tls_mtls_truststore \
  kmc-crypto-service:4.0.0
```

1. Create SystemD Unit file for container (if desired)
```bash
podman generate systemd -n -f --container-prefix='' kmc-crypto-service
sudo mv kmc-crypto-service.service /lib/systemd/system/
sudo chown root:root /lib/systemd/system/kmc-crypto-service.service
sudo chmod 0644 /lib/systemd/system/kmc-crypto-service.service
sudo systemctl daemon-reload
```

1. Start the container
Either:
```bash
sudo systemctl start kmc-crypto-service
```

*OR*

```bash
podman start kmc-crypto-service
```

### Deploying with podman-compose
Podman-compose uses YAML-formatted files to configure one or more services.  An example podman-compose file for the DCS Crypto Service Container can be found in kmc-resources/packaging/container/crypto-service/podman-compose-example.yml.  This example compose file uses podman secrets like the previous example to manage sensitive inputs.

1. Import the Image (optional, if image is available in a configured repository)
```bash
$ podman image load -i kmc-crypto-service-4.0.0.tar.gz
```

1. Configure Secrets
```bash
$ podman secret create tls_host_key /etc/pki/tls/private/ammos-server-key.pem
$ podman secret create tls_host_cert /etc/pki/tls/certs/ammos-server-cert.pem
$ podman secret create tls_ca_bundle /etc/pki/tls/certs/ammos-ca-bundle.crt
$ podman secret create tls_mtls_truststore /etc/pki/tls/private/ammos-mtls-truststore.jks
$ echo "changeit" | podman secret create tls_mtls_truststore_pass -
$ podman secret create crypto_keystore /msn_data/crypto/crypto_keystore.bcfks
$ echo "s00p3rs3cr3tp@ssph4se" | podman secret create crypto_keystore_pass -
```

1. Edit podman-compose-example.yml as needed for desired configuration.  
See the Crypto Service Container Configuration Options section above for details.

1. Use podman-compose to bring up the container:
```bash
podman-compose -f podman-compose-example.yml up -d
```

1. To shut down the container using podman-compose:
```bash
podman-compose -f podman-compose-example.yml down
```
