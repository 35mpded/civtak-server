This is an enhanced version of Cloud-RF's Docker wrapper for the official 'OG' CivTAK server. It fixes bugs, refines existing features and enables "Quick Connect" by using trusted certificates from "Let's Encrypt". *For quick setup, you can directly skip to section **2.1. Auto-Enrollment (Quick Connect) setup**. However, you will eventually need to read and understand the detailed information provided in this document.*
> Did you know that if your TAK End-user Devices (EUDs) are on the same network, you don't actually need a TAK server? If you don't need the additional features offered by the TAK server, consider creating a serverless network for TAK (aka ZeroTakServer) using the ZeroTier One application by ZeroTier, Inc. or setting up your own VPN. The ZeroTakServer has a limit of 32 users. Here you can find a great resource on this topic: https://www.civtak.org/2020/04/06/ztakserver-easy-light-weight-private/

# 1. REQUIREMENTS
- Debian-based operating system, such as Debian, Ubuntu, Raspberry Pi OS, and others
- Docker with compose (https://docs.docker.com/engine/install/ubuntu/ or https://docs.docker.com/engine/install/debian/)
- The official Docker TAK server release. You can obtain it from https://tak.gov/products/tak-server
- At least 4GB of RAM
- Network connection
-  The following dependencies have to be isntalled `git`, `unzip`, `net-tools`, `certbot`, and `openjdk-17-jre`. See section **1.1. Dependencies Installation**

## 1.1. Dependencies Installation
The following instellation steps were tested on Ubuntu 20.04.6 LTS (focal) and 22.04.3 LTS (jammy)
```
# Install the tools required by the script
sudo apt install git unzip net-tools certbot openjdk-17-jre
```

After installing the tools required by the script, proceed with the Docker Compose installation. *If the installation fails, refer to the documentation for guidance: [Ubuntu installation guide](https://docs.docker.com/engine/install/ubuntu/) or [Debian installation guide](https://docs.docker.com/engine/install/debian/).*
```
# Installing docker-compose
sudo apt install docker-compose

# Add the user to the docker group so it can run docker without sudo
sudo usermod -aG docker $USER

# Allow any user on the system to communicate with the Docker daemon
sudo chmod 666 /var/run/docker.sock

# Test if you can run docker without sudo. If you can the installation is successful
docker run hello-world
```
 
If you have installed the necessary dependencies, you can now proceed with the TAK installation.

# 2. TAK SETUP
The Docker wrapper is designed to install TAK and configure it to use one of the following authentication methods:
- Certificate Auto-Enrollment (aka Quick Connect)
- Certificate Manual-Enrollment (aka Data Packages)

Refer to the **4.1. TAK Authentication Methods** section of this document to determine the most suitable method for you. *Regardless of your selection, the server will operate as a Public Key Infrastructure (PKI), serving both as the Root Certificate Authority (the highest-level of trusted authority) and as an Intermediate CA, which will act on behalf of the root CA to sign and issue certificates to your clients, i.e., End-user devices (EUDs). The difference solely lies in how you plan/prefer to onboard your clients (EUDs).* 

## 2.1. Certificate Auto-Enrollment (Quick Connect) setup
The **Certificate Auto-Enrollment (Quick Connect)** setup uses "Let's Encrypt" to create a trusted certificate for the TAK server, allowing to rapidly onboard your End-user Devices (EUDs), i.e., clients, using only a username and password, eliminating the need for deployment packages.

### The installation method asumes the following:
- You have installed the requirements. See section **1.1. Dependencies installation**
- You have a domain to which you can issue a "Let's Encrypt" certificate. If not, consider using a free service such as noip.com, desec.io, or similar. 
- You have already configured an "A" record in your DNS to point the domain to the TAK server's IP address.
- You already port-forwarded the necessary ports and configured your operating system's firewall to allow traffic on them. Refer to section **4.3. Port Info** of this document for detailed information on the ports used by TAK.
	> https://portforward.com/ offers an extensive list of routers and instructions to reference.

Now that that's out of the way, carefully follow the **2.1.1. Setup Instructions** section.

### 2.1.1. Setup Instructions
*During the setup, you may encounter prompts from the setup script not mentioned in this section. This is because the script handles various problems, such as when TAK is already installed or other conflicts which can break the TAK server. You shouldn't see such prompts during the initial installation, but if you do, follow these prompts and address any actions they request. If you feel like you've broken the installation, run `sudo ./scripts/cleanup.sh` to clean up and start over.*

- The very first thing you'll need to do is clone the civtak-server repository:
	 ```
	# Clone the repository to your user's home directory
	myuser@myserver:~/civtak-server$: git clone https://github.com/35mpded/civtak-server.git ~/civtak-server
	```

- Next, download the latest TAK Docker release, **TAKSERVER-DOCKER-X.X-RELEASE-XX.zip**, and place it in the `civtak-server` directory. You can get the latest release from the [TAK Product Center](https://tak.gov/products/tak-server).

- If you haven't already, set `civtak-server` as your working directory using the command `cd ~/civtak-server`, and then run the setup script. You will be prompted to confirm if you have completed certain actions. Select "y" if you have; otherwise, complete them.
	```
	# Allow execution of the setup script
	myuser@myserver:~/civtak-server$: chmod +x ./scripts/setup_le.sh
	
	# Execute the setup script
	myuser@myserver:~/civtak-server$: ./scripts/setup_le.sh
	```

- During the installation process, you will be prompted to provide a fully qualified domain name (FQDN) for which "Let's Encrypt" will issue a certificate. This domain name will be used for the TAK Auto-Enrollment (also known as Quick Connect) functionality.
	> If you haven't done so yet, now is the time to create an "A" record in your domain's DNS settings. 
	```
	# FQDN prompt from the civtak setup script
	# Here the input "tak.ddns.net" is just an example. You need to provide your actual domain
	myuser@myserver:~/civtak-server$: 
	...
	...
	Enter the domain name for TAK QuickConnect (e.g., tak.mydomain.local [excluding https://]): tak.ddns.net
	```

- After providing the domain name, you will be asked to choose between "Let's Encrypt" or a "Self-signed" certificate.
*Currently the script only supports "Let's Encrypt," so please choose that option.*
	```
	myuser@myserver:~/civtak-server$: 
	...
	...
	Do you want to use "Let's Encrypt" or "Self-signed" certificate? (Let's Encrypt [l] / Self-signed [c]): l
	```

- After selecting the "Let's Encrypt" option, the "Let's Encrypt" certbot utility will instruct you to add a DNS TXT record to your domain's DNS settings. This record serves as a challenge to validate that you control the domain you specified. Create the TXT record as specified by the certbot utility and wait for this change to propagate across DNS. Once the record has propagated, press 'Enter' to proceed. You can verify the propagation status by running any of the following commands or through the mxtoolbox.com website.
	```
	# tak.mydomain.local is just an example. Replace with your actual domain name.
	
	# Check for TXT record using DIG
	dig txt tak.mydomain.local _acme-challenge.tak.mydomain.local
	
	# Check for TXT record using nslookup
	nslookup -q=TXT _acme-challenge.tak.mydomain.local
	```
	> If you prefer using the HTTP challenge instead of the DNS challange, you can modify the `setup_le.sh` script. Search for `sudo certbot` in `setup_le.sh` and read the comments in the script for instructions. Keep in mind that there are two sections in the script where you need to make modifications. Additionally, this change requires port 80 to be forwarded and allowed on the system running the script.

- After the script generates the "Let's Encrypt" certificate and performs some additional actions in the background, it will prompt you for details regarding the general configuration of the TAK server. The only adjustment you should really consider is changing the memory allocation to 4GB (4000000), that is, if you have limited memory. The default values are generally fine for the remaining options unless you need specific changes. If that's the case, you probably know what you're doing. Press "enter" to accept the default values.
	```
	myuser@myserver:~/civtak-server$:
	...
	...
	The following prompts will gather information used for general configuration of the TAK server:
	Enter the username for the TAK administrator account. Default [webadmin]:
	Username set to: webadmin

	Which IP should TAK use for the Federation service and Rate limiter? Detected [10.0.0.4]
	Press 'enter' to use 10.0.0.4 or input a different address if this is incorrect:
	IP Address set to: 10.0.0.4

	Enter the amount of memory to allocate, in kB. Default [8000000]: 4000000
	TAK memory set to: 4000000
	```


- At some point, you'll be prompted again. This time, the setup script will ask for details about the PKI environment. Again, the default values are fine unless you know what you're doing. Press "enter" to accept the default values.
	```
	myuser@myserver:~/civtak-server$:
	...
	...
	The following prompts will gather information used for PKI setup:
	State (for cert generation). Default [Not applicable]:
	City (for cert generation). Default [Not applicable]:
	Organizational Name (for cert generation). Default [CivTAK]:
	Organizational Unit (for cert generation). Default [civtak.local]:
	Common Name (i.e. FQDN). Default/Recommended [tak.nordheed.com]:
	Certificate Authority password. Default [atakatak]:
	```

Beyond that, the setup script will generate the required certificates, configure the necessary files, launch the TAK server and a PostgreSQL database using Docker Compose. Upon completing the setup, you will be provided with a list of randomly generated passwords and a link to access the administrator web interface. To access the Marti dashboard (administrator web interface), you'll need to import the admin certificate into your browser. If you need help with this, refer to the section **5.1. Admin Login (Certificate Import)**
```
myuser@myserver:~/civtak-server$:
...
...
TAK server setup complete. Server is now running!

---------LOGIN INSTRUCTIONS-------

1. Import the /home/tak/civtak-server/tak/certs/files/webadmin.p12 certificate to your browser as per the README.md file
2. Login at https://10.0.0.4:8443 or https://tak.domain.local:8443 with your admin account.

---------PASSWORDS----------------

Admin user name: webadmin
Admin password: hiXz?u.(I46lN}TTf
PostgreSQL password: ;JxAp@`a!]%}b9vd;I5
PKCS12 and JKS passwords for `Let's Encrypt` certificate: Gci]B?FZI[uA65Uy~p
TAK Certificate Authority password: atakatak

---------WARNINGS-----------------

* MAKE NOTE OF YOUR PASSWORDS. THEY WON'T BE SHOWN AGAIN!
* You have a database listening on TCP 5432 which requires a login. However, you should still block this port with a firewall
* Following docker containers should automatically start with the Docker service from now on:
...
```

For more information on the TAK server, refer to the documentation on the TAK Product Center GitHub: https://github.com/TAK-Product-Center/Server/tree/main/src/docs

## 2.2. Manual-Enrollment (Data Packages) setup - WIP
The Manual-Enrollment setup uses platform specific deployment packages to onboard your End-user Devices (EUDs), i.e., clients. This authentication method is ideal for highly secure environments and situations where security is of utmost priority.

# 4. TAK TECHNICAL DETAILS
## 4.1. Authentication Methods
The TAK (Tactical Assault Kit) server uses X.509 certificates to achieve mutual authentication with its clients, i.e., End-user Devices (EUDs), and to encrypt the communication between clients and the server. Depending on the configuration in your `CoreConfig.xml`, the TAK server can either Auto-Enroll the certificate to your client device after providing a username and password or expect your device to present an existing certificate, which would be imported into the TAK client as a data package beforehand.
> Please be aware that on a TAK server with Auto-Enrollment and a trusted certificate, you will only need to provide a username and password to connect; a Data Package is not required. However, for a TAK server with Auto-Enrollment but without a trusted certificate, you'll need to provide a username and password, as well as a Data Package containing the intermediate CA certificate that the TAK client needs to trust. In both cases the client (i.e. the user) certificate will be Auto-Enrolled.

Both authentication methods can be set up to work on a TAK server that is either publicly exposed or hidden behind a VPN. Unfortunately, the documents in this repository will not provide instructions on how to integrate a TAK server into such a network. This is because of the numerous variables I cannot account for, such as the devices available to you, existing network topology and configuration, restrictions by your specific ISP, country, and so on. However, at some point I might provide a high-level overview.
> The communication between EUDs and the TAK server is already encrypted. However, when hidden behind a VPN or proxy, your TAK server will not be publicly exposed to prying eyes, further increasing the security for the TAK server itself and the connected to it EUDs. 

## 4.1.1. Certificate Manual-Enrollment (Data Packages): 
With the Certificate Manual-Enrollment (Data Packages) authentication method, you create platform-specific deployment packages (Android, iOS, or PC) and send them to the clients (EUDs). See section **4.2. Data Package Details** for more information. The clients (EUDs) then need to download the appropriate DataPackage.zip to their device and import it in their client app (iTAK, ATAK, WinTAK) to establish a connection to the TAK server. 

Although it may seem more complicated (rightfully so), it's the more secure authentication method, this is because brute-force attacks are not applicable. Furthermore, you can more easily integrate the server within a VPN network (or potentially even behind a proxy), providing extra privacy and security for the TAK server. The trade-off with this authentication method is that you'll need to create a data package for each individual user.

## 4.1.2. Certificate Auto-Enrollment (with Trust [aka Quick Connect]): 
With Certificate Auto-Enrollment (with Trust), clients (EUDs) can obtain their certificates directly from the server through the Quick Connect option of the TAK client (iTAK, ATAK, WinTAK) by providing a valid username and password. For Auto-Enrollment to work without a data package though, the client expects the TAK server to have a trusted (i.e. signed) certificate, which isn't easily obtainable. However, you can use the "Let's Encrypt" service, which is a free, automated, and open Certificate Authority (CA) that can issue trusted/signed certificates.
> Caution: Because the "Let's Encrypt" authority is publicly accessible, anyone could potentially generate a client (user) certificate and connect to your TAK server. To mitigate this, we do not use "Let's Encrypt" certificates for authentication. Instead, the script applies a "Let's Encrypt" certificate to the TAK authentication page via the cert_https connector on port 8446, which allows authentication (auto-enrollment of certificates) by using a username and password only.

Although this method makes it easier to onboard your EUDs, the trade-off is that it requires a more complex setup to integrate within a VPN network. Mainly because "Lets's Encrypt" can issue a certificate only to a pubicly facing domains. Most importantly, this makes it easier for a potential intruder to brute-force or steal the credentials, thereby reducing overall security. 

*Please be aware that if you want to use a Certificate Authority (CA) other than "Let's Encrypt," modifications to the script will be necessary. Additionally, you'll need to establish a process for renewing and creating certificates. This is due to the varying procedures among different providers, making it impossible to automate every variation.*

## 4.1.3. Certificate Auto-Enrollment (without Trust): 
This method is essentially the same as the "Certificate Manual-Enrollment (Data Packages)" approach, with a slight variation in the Data Packages and how you connect/authenticate to the server. The key difference is that the TAK server does not have a trusted certificate, consequently the EUD/client should import the truststore-intermediate-ca.p12 file, but not the present a client.p12 certificate, as it will be auto-enrolled by the TAK server. This means you need to provide a username, password, and data package (without the client certificate). See section **4.2. Data Package Details** for more information.

## 4.2. Data Package Details
Please note that Data Packages for iTAK (iPhone) might have a slightly different structure. I am unable to test the package on iTAK, since I do not own an iPhone and likely never will. Therefore, the following information is considered valid only for ATAK/WinTAK clients. To create a data package from scratch, follow the file and directory structure outlined below and make the specified modifications to the manifest.xml and server.conf as noted in the comments. 

Example Data Packages can be found here: https://github.com/35mpded/civtak-server/tree/main/DataPackages

### Description of packaged files: 
- **client.p12:** This file is the certificate that TAK expects for a specific EUD/client to present for user authentication.
- **truststore-intermediate-ca.p12:** This file holds the intermediate Certificate Authority's certificate. It must be imported by the TAK client to establish trust with the TAK server.
- **manifest.xml:** This file describes the structure and contents of the data package.
- **server.pref**: This file includes various configuration details that TAK uses to identify and connect to the server.

## 4.2.1. Manual-Enrollment (Data Packages)
### Directory Structure for Manual-Enrollment
```
./
├── MANIFEST
│   └── manifest.xml
└── certs
    ├── truststore-intermediate-ca.p12
    ├── client.p12
    └── server.pref
```

### Example server.pref for Manual-Enrollment
```xml
<?xml version='1.0' encoding='ASCII' standalone='yes'?>
<preferences>
  <preference version="1" name="cot_streams">
    <entry key="count" class="class java.lang.Integer">1</entry>
    <!-- Replace `TAK Server` with whatever name you want to be displayed in the app -->
    <entry key="description0" class="class java.lang.String">TAK Server</entry>
    <entry key="enabled0" class="class java.lang.Boolean">true</entry>
    <!-- Replace `TAKSERVER` with your IP/domain address -->
    <entry key="connectString0" class="class java.lang.String">TAKSERVER:8089:ssl</entry>
  </preference>
  <preference version="1" name="com.atakmap.app_preferences">
    <entry key="displayServerConnectionWidget" class="class java.lang.Boolean">true</entry>
    <!-- Replace with the location and name of the truststore-intermediate-ca.p12 certificate file -->
    <!-- E.g. truststore-intermediate-ca.tak.mydomain.local.p12 -->
    <entry key="caLocation" class="class java.lang.String">cert/truststore-intermediate-ca.p12</entry>
    <!-- Replace `PASSWORD` with the actual CA password (default is atakatak) -->
    <entry key="caPassword" class="class java.lang.String">PASSWORD</entry>
    <!-- Replace `PASSWORD` with the actual password for the client certificates (default is atakatak) -->
    <entry key="clientPassword" class="class java.lang.String">PASSWORD</entry>
    <!-- Replace with the location and name of the client.p12 certificate file -->
    <!-- This should correspond to an actual user in TAK, e.g. toxic, so the certificate will be toxic.p12 -->
    <entry key="certificateLocation" class="class java.lang.String">cert/client.p12</entry>
    <!-- Replace the below lines however you want to identify your TAK client/EUD -->
    <entry key="locationCallsign" class="class java.lang.String">WinTAK</entry>
    <entry key="locationTeam" class="class java.lang.String">Blue</entry>
    <entry key="atakRoleType" class="class java.lang.String">Team Member</entry>
  </preference>
</preferences>
```

### Example manifest.xml for Manual-Enrollment
```xml
<MissionPackageManifest version="2">
  <Configuration>
    <!-- Replace `UID-HERE` with something random from here https://www.uuidgenerator.net or whatever -->
    <Parameter name="uid" value="UID-HERE"/>
    <!-- Replace `DataPackage1.zip` with the name you plan to create for your .zip data pacakge file -->
    <Parameter name="name" value="DataPackage1.zip"/>
    <Parameter name="onReceiveDelete" value="true"/>
  </Configuration>
  <Contents>
    <!-- Replace `server.pref` with the actual location and name of the .pref file -->
    <Content ignore="false" zipEntry="certs/server.pref"/>
    <!-- Replace with the location and name of the truststore-intermediate-ca.p12 certificate file -->
    <!-- E.g. truststore-intermediate-ca.tak.mydomain.local.p12 -->
    <Content ignore="false" zipEntry="certs/truststore-intermediate-ca.p12 "/>
    <!-- Replace with the location and name of the client.p12 certificate file -->
    <!-- This should correspond to an actual user in TAK, e.g. toxic, so the certificate will be toxic.p12 -->
    <Content ignore="false" zipEntry="certs/client.p12"/>
  </Contents>
</MissionPackageManifest>
```

## 4.2.2. Data Package (Auto-Enrollment [without Trust])

### Directory Structure for Auto-Enrollment
```
./
├── MANIFEST
│   └── manifest.xml
└── certs
    ├── truststore-intermediate-ca.p12
    └── server.pref
```

### Example server.pref for Auto-Enrollment
```xml
<?xml version='1.0' encoding='ASCII' standalone='yes'?>
<preferences>
  <preference version="1" name="cot_streams">
    <entry key="count" class="class java.lang.Integer">1</entry>
    <!-- Replace `TAK Server` with whatever name you want to be displayed in the app -->
    <entry key="description0" class="class java.lang.String">TAK Server</entry>
    <entry key="enabled0" class="class java.lang.Boolean">true</entry>
    <!-- Replace `TAKSERVER` with your IP/domain address -->
    <entry key="connectString0" class="class java.lang.String">TAKSERVER:8089:ssl</entry>
    <!-- Replace with the location and name of the truststore-intermediate-ca.p12 certificate file -->
    <!-- E.g. truststore-intermediate-ca.tak.mydomain.local.p12 -->
    <entry key="caLocation0" class="class java.lang.String">cert/truststore-intermediate-ca.p12</entry>
    <!-- Replace `PASSWORD` with the actual CA password (default is atakatak) -->
    <entry key="caPassword0" class="class java.lang.String">PASSWORD</entry>
    <entry key="enrollForCertificateWithTrust0" class="class java.lang.Boolean">true</entry>
    <entry key="useAuth0" class="class java.lang.Boolean">true</entry>
    <entry key="cacheCreds0" class="class java.lang.String">Cache credentials</entry>
  </preference>
  <preference version="1" name="com.atakmap.app_preferences">
    <entry key="displayServerConnectionWidget" class="class java.lang.Boolean">true</entry>
    <!-- Replace the below lines however you want to identify your TAK client/EUD -->
    <entry key="locationCallsign" class="class java.lang.String">WinTAK</entry>
    <entry key="locationTeam" class="class java.lang.String">Blue</entry>
    <entry key="atakRoleType" class="class java.lang.String">Team Member</entry>
  </preference>
</preferences>
```

### Example manifest.xml for Auto-Enrollment
```xml
<MissionPackageManifest version="2">
  <Configuration>
    <!-- Replace `UID-HERE` with something random from here https://www.uuidgenerator.net or whatever -->
    <Parameter name="uid" value="UID-HERE"/>
    <!-- Replace `DataPackage2.zip` with the name you plan to create for your .zip data pacakge file -->
    <Parameter name="name" value="DataPackage2.zip"/>
    <Parameter name="onReceiveDelete" value="true"/>
  </Configuration>
  <Contents>
    <!-- Replace `server.pref` with the actual location and name of the .pref file -->
    <Content ignore="false" zipEntry="certs/server.pref"/>
    <!-- Replace with the location and name of the truststore-intermediate-ca.p12 certificate file -->
    <!-- E.g. truststore-intermediate-ca.tak.mydomain.local.p12 -->
    <Content ignore="false" zipEntry="certs/truststore-intermediate-ca.p12 "/>
  </Contents>
</MissionPackageManifest>
```

## 4.3. Port Info
Be cautious when exposing these ports, as some do not run secure protocols! For added security, use a VPN service like OpenVPN or restrict access on those ports to specific IP addresses.

This table shows the ports, their protocol, direction, and purpose:
| SERVICE             | PROTOCOL | PORT                | SOURCE          | DESTINATION      | DIRECTION |
|---------------------|----------|---------------------|-----------------|------------------|-----------|
| TAK Signaling       | TCP/S    | 8089                | Client          | Server           | IN        |
| TAK API WebUI WebTAK| TCP/S    | 8443                | Client          | Server           | IN        |
| Federation          | TCP/S    | 8444 (Legacy), 9000 (v1), 9001 (v2) | Server | Server | IN |
| Certificate Provisioning | TCP/S | 8446             | Client          | Server           | IN        |
| TAK SA              | UDP      | 6969                | 239.2.3.1       | 239.2.3.1        | BOTH      |
| GeoChat             | UDP      | 18740               | 224.10.10.1     | 224.10.10.1      | BOTH      |
| FederationHUB WebUI | TCP/S    | 9100                | Client          | Server           | IN        |
| FederationHUB Federation | TCP/S | 9102 (v2)        | Server          | Server           | IN        |

## 4.4. Log files
TAK Server has several log files to provide information about relevant events that happen during execution. The log files are located in the `./civtak-server/tak/logs` directory. 

This table shows the name of the log files, and their function:
| Name of Log File                     | Purpose                                                                 |
|--------------------------------------|-------------------------------------------------------------------------|
| takserver-messaging.log              | Execution-level information about the messaging process, including client connection events, error messages and warnings. |
| takserver-api.log                    | Execution-level information about the API process, including error messages and warnings. |
| takserver-messaging-console.log      | Java Virtual Machine (JVM) informational messages and errors, for the messaging process. |
| takserver-api-console.log            | Java Virtual Machine (JVM) informational messages and errors, for the API process. |

# 5. TAK MANAGEMENT
## 5.1. Admin Login (Certificate Import)
To access your administrator dashboard (Marti), TAK requires mutual TLS authentication (Client > Server, Server > Client) which is done using the admin certificate created during setup. Therefore, you need to import the admin certificate (default: `weadmin.p12`) into your browser. The name of this certificate is the same as the one you entered in the **"TAK administrator account"** field during the **"general configuration of the TAK server"** step. The admin certificate will be located in `./tak/certs/files/` after it's generated by the script.

### Google Chrome:
- Go to **"Settings" → "Privacy and Security" → "Security" → "Manage Certificates".**
- Navigate to **"Your certificates".**
- Press the **"Import"** button and select your `.p12` file (default password is `atakatak`).

*The web UI should now be accessible at the address provided by the setup script.*

### Mozilla Firefox
- Go to **"Settings" --> "Privacy & Security"** --> scroll down to **"Certificates"** section.
- Click the button **"View Certificates"**
- Choose **"Your Certificates"** section and **"Import"** your `.p12` certificate (Default password is `atakatak`)
- Choose the **"Authorities"** section
- Locate **"TAK"** line, there should be your certificate name displayed underneath it
- Click your certificate name and press button **"Edit Trust"**
- **TICK** the box with **"This certificate can identify web sites"** statement, then click **"OK"**

*The web UI should now be accessible at the address provided by the setup script.*

## 5.2. TAK Server Maintenance
### Start TAK server after shutdown
Make sure you are in the main `civtak-server` directory and append the `-d` flag to run the process in the background.
```
# Set civtak-server as a working directory
cd ~/civtak-server

# Start the containers
docker compose up -d
```

### Shutdown running TAK server
Make sure you are in the main `civtak-server` directory.

```
# Set civtak-server as a working directory
cd ~/civtak-server

# Stop the containers
docker compose down
```

### Open an interactive shell
You can open an interactive shell in either the TAK or DB Docker container using the following commands:
```
# Open an interactive shell in the TAK container
docker exec -it civtak-server_tak_1 bash

# Open an interactive shell in the DB container
docker exec -it civtak-server_db_1 bash
```

Alternatively, you can use the `CONTAINER ID` instead of the name to open an interactive shell.
```
# Find the `CONTAINER ID`
docker ps

# Open an interactive shell in that container. E.g. docker exec -it aa9416fc42de bash
docker exec -it <CONTAINER ID> bash
```

### Execute shell commands
You can also run commands in the Docker container without opening an interactive shell.
```
# Tail the takserver.log file from the docker container
docker exec -it tak-server-tak-1 tail -f /opt/tak/logs/takserver.log
```

## 5.3. TAK Files & Logs
Since the container volumes are mapped to a local directory, you can inspect the TAK server files located in `./civtak-server/tak` or view the logs in `./civtak-server/tak/logs` directly, without needing to interact with the Docker container.

## 5.4. Creating Data Packages (WIP):
*You can ignore this section if you're using Auto-Enrollment (with Trust [Quick Connect])*

### Creating Data Packages for Manual-Enrollment
### Create Data Packages for Auto-Enrollment (without Trust):

# 6. FAQ
The **Frequently Asked Questions** is in seperate document here: https://github.com/35mpded/civtak-server/blob/main/docs/FAQ.md

# 7. USEFUL LINKS
- TAK server on TAK.gov: https://tak.gov/products/tak-server
- ATAK-CIV on Google Play: https://play.google.com/store/apps/details?id=com.atakmap.app.civ&hl=en_GB&gl=US
- iTak on Apple App store: https://apps.apple.com/my/app/itak/id1561656396
- WinTAK-CIV on TAK.gov: https://tak.gov/products/wintak-civ
- ZeroTAKServer-Easy, Light-Weight & Private: https://www.civtak.org/2020/04/06/ztakserver-easy-light-weight-private/
- Documentation / References: https://www.civtak.org/documentation/
- The Official TAK Server Configuration Guide: https://github.com/TAK-Product-Center/Server/blob/main/src/docs/TAK_Server_Configuration_Guide.pdf
- Using External Certificate Authorities to sign your TAK Server: https://mytecknet.com/lets-sign-our-tak-server/
- Let's Build a TAK Server - 5.0 UPDATE: https://mytecknet.com/lets-build-a-tak-server/
