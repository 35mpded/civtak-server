#!/bin/bash

color() {
    STARTCOLOR="\e[$2";
    ENDCOLOR="\e[0m";
    export "$1"="$STARTCOLOR%b$ENDCOLOR"
}
color info 96m
color success 92m
color warning 93m
color danger 91m

### Exit the script if executed as sudo
if [ "$EUID" -eq 0 ]; then
  printf $danger "ERROR: You should install this as a normal user. Elevated privileges (sudo) are only required to clean up a previous install, e.g., sudo ./scripts/cleanup.sh\n"
  exit 1
fi

### Check if required tools are installed
printf $warning "Performing a check to ensure all required tools for the script are installed.."
# List of required tools with their respective commands to check installation
declare -A required_tools
required_tools=(
    ["git"]="git --version"
    ["unzip"]="unzip -v"
    ["net-tools"]="ifconfig"
    ["certbot"]="certbot --version"
    ["openjdk-17-jre"]="dpkg -l | grep openjdk-17-jre"
    ["docker-compose"]="docker-compose --version"
)

# Check each required tool and store missing ones
missing_tools=()
for tool in "${!required_tools[@]}"; do
    if ! eval ${required_tools[$tool]} &> /dev/null; then
        missing_tools+=("$tool")
    fi
done

# Output result and exit if there are missing tools
if [ ${#missing_tools[@]} -eq 0 ]; then
    printf $success "\nAll required tools are installed and functioning properly. Proceeding with setup..\n"
else
    printf $danger "\nThe following tools are either not installed or not functioning properly:\n"
    for tool in "${missing_tools[@]}"; do
        echo "- $tool"
    done
    printf $danger "\nThe script will now exit. Please fix any issues with the tools listed above before proceeding with the setup.\n"
    exit 1
fi

### Ask the user if they have performed the necessary steps before setup
printf $warning "\nStep 1. Download the official docker image as a zip file from https://tak.gov/products/tak-server\n"
printf $warning "Step 2. Place the zip file in this civtak-server folder.\n"
printf $warning "Step 3. Create an A record for your domain to point to this server.\n"
printf $warning "Step 4. Port forward the necessary ports. Refer to the 4.2 Port Info section at https://github.com/35mpded/civtak-server/blob/main/README.md\n"
while true; do
    printf $info "\nHave you performed the above steps? (y/n): "; read choice
    if [ "$choice" == "y" ] || [ "$choice" == "Y" ]; then
        break
    elif [ "$choice" == "n" ] || [ "$choice" == "N" ]; then
        printf $danger "Please perform the required steps before running this script.\n"
        exit 1
    else
        printf $danger "Invalid choice, please enter 'y' for yes or 'n' for no.\n"
    fi
done
printf $success "Proceeding with the installation..\n\n"

DOCKER_COMPOSE="docker-compose"

if ! command -v docker-compose
then
	DOCKER_COMPOSE="docker compose"
	echo "Docker compose command set to new style $DOCKER_COMPOSE"
fi

arch=$(dpkg --print-architecture)

DOCKERFILE=docker-compose.yml

if [ $arch == "arm64" ];
then
	DOCKERFILE=docker-compose.arm.yml
	printf "\nBuilding for arm64..\n" "info"
fi


### Check if required ports are in use by anything other than docker
netstat_check () {
        printf $warning "\nSTATUS: Performing a check if required ports are free.."
        # Feel free to remove port 80 if you generated the `Let's Encrypt` certificate some otherway
	ports=(5432 8089 8443 8444 8446 9000 9001 80)

	for i in ${ports[@]};
	do
		netstat -lant | grep -w $i
		if [ $? -eq 0 ];
		then
			printf $warning "\nAnother process is still using port $i. Either wait or use 'sudo netstat -plant' to find it, then 'ps aux' to get the PID and 'kill PID' to stop it and try again\n"
			exit 0
		else
			printf $success "\nPort $i is available.."
		fi
	done
}

tak_folder () {
        printf $warning "\n\nSTATUS: Performing a check if the folder \`tak\` exists after previous install or attempt.."
	### Check if the tak folder exists from a previous installation or attempt, and either remove it or let the user decide what to do.
	if [ -d "./tak" ]
	then
	    printf $danger "\nDirectory 'tak' already exists. This will be removed along with the docker volume, do you want to continue? (y/n): "
	    read dirc
	    if [ $dirc == "n" ];
	    then
	    	printf "Exiting now.."
	    	sleep 1
	    	exit 0
	    elif [ $dirc == "no" ];
	    then
	    	printf "Exiting now.."
	    	sleep 1
	    	exit 0
	   	fi
		rm -rf tak
		rm -rf /tmp/takserver
		docker volume rm --force tak-server_db_data
	fi
}


checksum () {
	printf "\nChecking for TAK server release files (..RELEASE.zip) in the directory..\n"
	sleep 1

	if [ "$(ls -hl *-RELEASE-*.zip 2>/dev/null)" ];
	then
		printf $warning "SECURITY WARNING: Make sure the checksums match! You should only download your release from https://tak.gov/products/tak-server\n"
		for file in *.zip;
		do
			printf "Computed SHA1 Checksum: "
			sha1sum $file
			printf "Computed MD5 Checksum: "
			md5sum $file
		done
		printf "\nVerifying checksums against known values for $file..\n"
		sleep 1
		printf "SHA1 Verification: "
		sha1sum --ignore-missing -c tak-sha1checksum.txt
		if [ $? -ne 0 ];
		then
			printf $danger "SECURITY WARNING: The file is either different OR is not listed in the known releases.\nDo you really want to continue with this setup? (y/n): "
			read check
			if [ "$check" == "n" ];
			then
				printf "\nExiting now.."
				exit 0
			elif [ "$check" == "no" ];
			then
				printf "Exiting now.."
				exit 0
			fi
		fi
		printf "MD5 Verification: "
		md5sum --ignore-missing -c tak-md5checksum.txt
		if [ $? -ne 0 ];
		then
			printf $danger "SECURITY WARNING: The file is either different OR is not listed in the known releases.\nDo you really want to continue with this setup? (y/n): "
			read check
			if [ "$check" == "n" ];
			then
				printf "\nExiting now.."
				exit 0
			elif [ "$check" == "no" ];
			then
				printf "Exiting now.."
				exit 0
			fi
		fi
	else
		printf $danger "Please download the release of docker image as per instructions in README.md file. Exiting now..\n"
		sleep 1
		exit 0
	fi
}

# Function to generate a secure random password
#
# This func generates a password with at least 15 characters, including
# at least one uppercase letter, one lowercase letter, one number, and one
# special character from the list [-_!@#$%^*(){}[]+=~`|:;<>,./?].
# It then randomizes the characters and appends extra random characters
# to achieve a password length between 15 and 20 characters.
#
# Usage: ./generate_password.sh
#
# Example output: Generated password: G2*4pF!s7~E%hYqL
#
generate_password() {
    length=$((RANDOM % 6 + 15))
    uppercase="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    lowercase="abcdefghijklmnopqrstuvwxyz"
    numbers="0123456789"
    ### Known problematic characters: [\&'] and likely others.
    ### The `&` symbol breaks deployment, possibly due to something outside of this script but I'm not sure tbh.
    ### Note that changes to the list of special character is very risky.
    special_chars='-_!@#$%^*(){}[]+=~`|:;<>,./?'

    password=""
    password+="${uppercase:RANDOM % ${#uppercase}:1}"
    password+="${lowercase:RANDOM % ${#lowercase}:1}"
    password+="${numbers:RANDOM % ${#numbers}:1}"
    password+="${special_chars:RANDOM % ${#special_chars}:1}"

    remaining_length=$((length - 4))
    all_chars="$uppercase$lowercase$numbers$special_chars"
    for i in $(seq 1 $remaining_length); do
        password+="${all_chars:RANDOM % ${#all_chars}:1}"
    done

    ### Shuffle the password characters
    echo "$password" | fold -w1 | shuf | tr -d '\n'
}

### Function to escape special characters that will break sed
escape_sed() {
    local input_string="$1"
    local escaped_string=""
    local char

    ### Iterate over each character in the input string
    for (( i=0; i<${#input_string}; i++ )); do
        char=${input_string:i:1}

        ### List of characters that need to be escaped in sed
        case "$char" in
            '/'|'.'|'*'|'['|']'|'('|')'|'{'|'}'|'\'|'&'|'^'|'$'|'|'|'?'|'+')
                escaped_string+="\\$char"  # Append a backslash to escape in sed
                ;;
            *)
                escaped_string+="$char"
                ;;
        esac
    done

    ### Output the escaped string without adding single quotes
    echo -n "$escaped_string"
}


netstat_check
tak_folder
if [ -d "tak" ]
then
	printf $danger "Failed to remove the tak folder. You will need to do this as sudo: sudo ./scripts/cleanup.sh\n"
	exit 0
fi
checksum

### Prompt the user for the domain name they want to use
printf $info "\nEnter the domain name for TAK QuickConnect (e.g., tak.mydomain.local [excluding https://]): "
read domain

### Function to process and convert the `Let's Encrypt` certificate
### NOTE: Currently there isn't any check if the keystore was success.
convertlecert() {
    ### Generate the password for the JAVA keystore and PKCS12
    export pkcs12_password=$(generate_password)
    #### Create a PKCS12 certificate from the signed Let's Encrypt certificate and private key
    printf $warning "\nSTATUS: Converting the X.509 \`Let's Encrypt\` certificate to PKCS12 format (${domain}-le.p12).."
    ### Create a PKCS12 certificate from the signed `Let's Encrypt` certificate and private key
    sudo openssl pkcs12 -export -in "/etc/letsencrypt/live/$domain/fullchain.pem" -inkey "/etc/letsencrypt/live/$domain/privkey.pem" -out "./lets_encrypt/${domain}-le.p12" -name $domain -passout pass:"$pkcs12_password"
    printf $success "\n./lets_encrypt/${domain}-le.p12 created successfully!\n"
    printf $warning "\nSTATUS: Creating a Java Keystore (${domain}-le.jks) from the PKCS12 certificate..\n"
    ### Prepare a `here-string` newline-separated string with the password repeated three times.
    ### This string will be used to input the password when prompted, as there is no command line option to provide it directly.
    input_keytool=$(printf "%s\n" "$pkcs12_password" "$pkcs12_password" "$pkcs12_password")
    ### Create a Java Keystore from the PKCS12 certificate
    sudo keytool -importkeystore -destkeystore "./lets_encrypt/${domain}-le.jks" -srckeystore "./lets_encrypt/${domain}-le.p12" -srcstoretype pkcs12 <<< "$input_keytool"
    printf $success "./lets_encrypt/${domain}-le.jks created successfully!\n"
}

### Function to process a custom certificate
selfsigned() {
    printf $danger "Self-signed certificate setup is not implemented, yet! Script will now stop..\n"
    exit 0
}

### Function to repeatedly ask for a valid choice between `Let's Encrypt` and Self-signed certificate
get_cert_type() {
    while true; do
        printf $info "Do you want to use \`Let's Encrypt\` or a Self-signed certificate? (Let's Encrypt [l] / Self-signed [s]): "
        read cert_type
        if [ "$cert_type" == "l" ] || [ "$cert_type" == "s" ]; then
            break
        else
            printf $danger "Invalid choice, please enter 'l' for Let's Encrypt or 's' for Self-signed.\n"
        fi
    done
}

### Prompt for the certificate type (`Let's Encrypt` or Self-signed)
get_cert_type

### Execute the appropriate flow based on the user's selection
if [ "$cert_type" == "s" ]; then
    selfsigned
else
    if [ ! -f "./lets_encrypt/${domain}-le.jks" ]; then
        ### File does not exist: proceed to create a `Let's Encrypt` certificate
        printf $warning "\nSTATUS: ${domain}-le.jks does not exist. Creating a \`Let's Encrypt\` certificate now..\n"

        ### Run certbot utility and check its exit status
	# Uncomment the below line and comment the next one if you do not want to use DNS challenges. Note: It will require port 80 to be forwarded and allow traffic on the host.
        # sudo certbot certonly --standalone -d "$domain"
	sudo certbot --manual --preferred-challenges dns certonly -d "$domain"
        certbot_status=$?

        if [ $certbot_status -ne 0 ]; then
            printf $danger "\nERROR: An error was found. Script will now stop, resolve any issues with \`Let's Encrypt\`, and then retry.\n"
            exit 1
        else
            printf $success "Certbot action on domain $domain completed successfully!\n"
            convertlecert
        fi
    else
        ### File exists: prompt to proceed with the existing certificate
        while true; do
            printf $danger "WARNING: Do you want to proceed with the existing JAVA keystore ${domain}-le.jks? [Selecting \"no\" will delete it (y/n)]: "
            read use_existing

            if [ "$use_existing" == "y" ] || [ "$use_existing" == "yes" ]; then
                printf $info "\nPlease enter the password for the ${domain}-le.jks keystore:"
                read -s pkcs12_password

                ### Attempt to list the keystore contents using the provided password.
                ### This is esentially used to verify if the password is correct, based on the exit status of the command.
                keytool -list -keystore "./lets_encrypt/${domain}-le.jks" -storepass "$pkcs12_password" > /dev/null 2>&1
                keytool_status=$?

                if [ $keytool_status -ne 0 ]; then
                    printf $danger "\nERROR: Password test failed. The provided password is incorrect, script will now stop.\n"
                    exit 1  # Exit the script with an error status
                else
                    printf $success "\nPassword test successful. The script will proceed with keystore ${domain}-le.jks.\n"
                    break  # Exit the loop and continue with the script
                fi
            elif [ "$use_existing" == "n" ] || [ "$use_existing" == "no" ]; then
                ### Directly create a new `Let's Encrypt` certificate without asking again
                rm -f ./lets_encrypt/${domain}-le*
                printf $warning "\nSTATUS: Creating a new \`Let's Encrypt\` certificate for $domain..\n"
                printf $danger "CAUTION: If you have an existing certificate and only intend to create a new JAVA keystore without renewing the certificate, choose option [1]. Otherwise, select option [2].\n"

                ### Run certbot utility and check the exit status
                # Uncomment the below line and comment the next one if you do not want to use DNS challenges. Note: It will require port 80 to be forwarded and allow traffic on the host.
                # sudo certbot certonly --standalone -d "$domain"
	        sudo certbot --manual --preferred-challenges dns certonly -d "$domain"
                certbot_status=$?

                if [ $certbot_status -ne 0 ]; then
                    printf $danger "\nAn error was found. Script will now stop, resolve any issues with \`Let's Encrypt\`, and then retry.\n"
                    exit 1
                else
                    printf $success "Certbot action on domain $domain completed successfully!\n"
                    convertlecert
                fi
                break
            else
                printf $danger "\nInvalid choice, please enter 'y' for Yes or 'n' for No.\n"
            fi
        done
    fi
fi
### Adjust correct ownership of the `lets_encrypt` directory and its contents to avoid permission issues.
sudo chown -R $USER:$USER ./lets_encrypt/

# The actual container setup starts here

### Vars

release=$(ls -hl *.zip | awk '{print $9}' | cut -d. -f -2)

printf $danger "\nWARNING: Pausing to let you know release version $release will be setup in 5 seconds.\nIf this is wrong, hit Ctrl-C now..\n" 
sleep 5


## Set up directory structure
if [ -d "/tmp/takserver" ]
then
	rm -rf /tmp/takserver
fi

# Ensuring the script can find `ifconfig` and other utilities.
export PATH=$PATH:/sbin

# unzip or 7z?
if ! command -v unzip
then
	if ! command -v 7z
	then
		printf $danger "\nThe script cannot decompress the TAK release because both the unzip and 7z utilities are not functioning properly!\n"
		printf $danger "Please troubleshoot the issue and refer to the script documentation: https://github.com/35mpded/tak-server/blob/main/README.md\n"
                printf $danger "The script will now exit..\n"
		exit 1
	else
		7z x $release.zip -o/tmp/takserver
                printf $success "\nTAK release decompressed using 7z completed successfully!\n"
	fi
else
	unzip $release.zip -d /tmp/takserver
        printf $success "\nTAK release decompressed using 7z completed successfully!\n"
fi

if [ ! -d "/tmp/takserver/$release/tak" ]
then
	printf $danger "\nDecompressed TAK release was NOT found at /tmp/takserver/$release\n"
	printf $danger "Please troubleshoot the issue and refer to the script documentation: https://github.com/35mpded/tak-server/blob/main/README.md\n"
        printf $danger "The script will now exit..\n"
	exit 1
fi

mv -f /tmp/takserver/$release/tak ./
chown -R $USER:$USER tak

cp ./scripts/configureInDocker1.sh ./tak/db-utils/configureInDocker.sh
cp ./postgresql1.conf ./tak/postgresql.conf
cp ./scripts/takserver-setup-db-1.sh ./tak/db-utils/takserver-setup-db.sh
# Moving the TAK config to the docker volume of the TAK container.
# The config uses a docker alias of postgresql://tak-database:5432/
cp ./CoreConfig.xml ./tak/CoreConfig.xml
# Set up the directory where TAK stores certificates and move the Let's Encrypt certificate into it.
# Note that this directory will be automatically created by TAK at a later stage, but we're creating it now because we need it.
mkdir ./tak/certs/files
cp "./lets_encrypt/${domain}-le.jks" ./tak/certs/files

printf $warning "\n\nThe following prompts will gather information used for general configuration of the TAK server:"
## Set admin username and password, and ensure it meets validation criteria
printf $info "\nEnter the username for the TAK administrator account. Default [webadmin]: "; read user
if [ -z "$user" ];
then
    user="webadmin"
fi
printf $success "Username set to: $user\n"
export password=$(generate_password)

## Set postgres password and ensure it meets validation criteria
export pgpassword=$(generate_password)

# get IP Address used by the docker host
NIC=$(route | grep default | awk '{print $8}' | head -n 1)
detected_IP=$(ip addr show $NIC | grep -m 1 "inet " | awk '{print $2}' | cut -d "/" -f1)

printf $info "Which IP should TAK use for the Federation service and Rate limiter? Detected [$detected_IP]\nPress 'enter' to use $detected_IP or input a different address if this is incorrect: "; read IP
if [ -z "$IP" ];
then
    IP=$detected_IP
fi
printf $success "IP Address set to: $IP\n"

# Replaces the `db-password` placeholder with the generated postgresql password.
sed -i "s|db-password|$(printf '%q' "$pgpassword")|g" tak/CoreConfig.xml


# Replaces HOSTIP for rate limiter and Fed server. Database URL is a docker alias of tak-database
sed -i "s/HOSTIP/$IP/g" tak/CoreConfig.xml

# Better memory allocation:
# By default TAK server allocates memory based upon the *total* on a machine.
# In the real world, people not on a gov budget use a server for more than one thing.
# Instead we allocate a fixed amount of memory
printf $info "Enter the amount of memory to allocate, in kB. Default [8000000]:"; read mem
if [ -z "$mem" ];
then
	mem="8000000"
fi
printf $success "TAK memory set to: $mem"

# Set the memory allocation specified above.
sed -i "s%\`awk '/MemTotal/ {print \$2}' /proc/meminfo\`%$mem%g" tak/setenv.sh

# Set variables for generating CA, intermediate CA and client certs
# For simplicity, the same password ($CAPASS) is used for both individual certificates and the CA.TAK stores the CA password as $CAPASS, while the password for individual certificates is stored in $PASS.
# If $PASS is not set, $CAPASS will be used for both the CA and client certificates.
# You can make the password for individual certificates separate from the CA password, but you need to reflect this change in the script.

printf $warning "\n\nThe following prompts will gather information used for PKI setup:\n"
printf $info "State (for cert generation). Default [Not applicable]: "; read state
printf $info "City (for cert generation). Default [Not applicable]: "; read city
printf $info "Organizational Name (for cert generation). Default [CivTAK]:"; read org
printf $info "Organizational Unit (for cert generation). Default [civtak.local]:"; read orgunit
printf $info "Common Name (i.e. FQDN). Default/Recommended [$domain]:"; read cn
printf $info "Certificate Authority password. Default [atakatak]: "; read -s capass

if [ -z "$state" ];
then
    state="Not applicable"
fi

if [ -z "$city" ];
then
    city="Not applicable"
fi

if [ -z "$org" ];
then
    org="CivTAK"
fi

if [ -z "$orgunit" ];
then
    orgunit="civtak.local"
fi

if [ -z "$cn" ];
then
    cn="$domain"
fi

if [ -z "$capass" ];
then
    capass="atakatak"
fi
printf $warning "\nProceeding with the following certificate details:"
printf $success "\nState: $state"
printf $success "\nCity: $city"
printf $success "\nOrg. Name: $org"
printf $success "\nOrg. Unit: $orgunit"
printf $success "\nCommon Name (FQDN). Unit: $cn"
printf $success "\nCertificate Authority password: $capass"
# Update local env
# Unfortunetly `Country` is hardcoded as `US` in incert-metadata.sh. Can't do anything about that.
export STATE=$state
export CITY=$city
export ORGANIZATION=$org
export ORGANIZATIONAL_UNIT=$orgunit
export CAPASS=$capass
export CN=$cn

# Writes variables to a .env file for docker-compose
cat << EOF > .env
STATE=$state
CITY=$city
ORGANIZATION=$org
ORGANIZATIONAL_UNIT=$orgunit
CAPASS=$capass
CN=$cn
EOF

printf $warning "\nUpdating config files..\n\n"
# Updaing the config files with the certificate password
# Characters that can break sed are escaped through printf.
sed -i "s|atakatak|$(printf '%q' "$CAPASS")|g" ./tak/TAKIgniteConfig.xsd
sed -i "s|atakatak|$(printf '%q' "$CAPASS")|g" ./tak/CoreConfig.xml

# Update the name of the intermediate certificate
sed -i "s/intermediate_ca/$cn/g" tak/CoreConfig.xml

# Update the name of the server certificate
sed -i "s/server_cert.jks/$cn.jks/g" tak/CoreConfig.xml

# Update the certificate for QUICK connect
sed -i "s/takserver-le.jks/${domain}-le.jks/g" tak/CoreConfig.xml

# Update the password for QUICK connect certificate
# Characters that can break sed are escaped through printf.
sed -i "s|le-password|$(printf '%q' "$pkcs12_password")|g" tak/CoreConfig.xml

### Runs through setup, starts both containers
printf $warning "Starting both containers and their setup..\n"
$DOCKER_COMPOSE --file $DOCKERFILE up  --force-recreate -d

### Setup the certificates
printf $warning "\nProceeding with certificate generation using the provided details.."
while :
do
    sleep 10 # let the PG stderr messages conclude...
    printf $warning "\n------------CERTIFICATE GENERATION--------------\n"
    $DOCKER_COMPOSE exec tak bash -c "cd /opt/tak/certs && ./makeRootCa.sh --ca-name root.'${cn}'"
    if [ $? -eq 0 ]; then
        # Adding CA certificate generation after root CA creation
        $DOCKER_COMPOSE exec tak bash -c "cd /opt/tak/certs && yes Y | ./makeCert.sh ca intermediate-ca.'${cn}'"
        if [ $? -eq 0 ]; then
            # Generate server certificate
            $DOCKER_COMPOSE exec tak bash -c "cd /opt/tak/certs && ./makeCert.sh server $cn"
            if [ $? -eq 0 ]; then
                # Generate client certificate
                $DOCKER_COMPOSE exec tak bash -c "cd /opt/tak/certs && ./makeCert.sh client $user"
                if [ $? -eq 0 ]; then
                    # Set permissions so the user can write to certs/files
                    $DOCKER_COMPOSE exec tak bash -c "useradd $USER && chown -R $USER:$USER /opt/tak/certs/"
                    # Stop the Docker service
                    $DOCKER_COMPOSE stop tak
                    break
                else
                    sleep 5
                fi
            else
                sleep 5
            fi
        else
            sleep 5
        fi
    fi
done

printf $warning "Waiting for TAK server to go live. This should take <1m with an AMD64, ~2min on a ARM64 (Pi)\n"
$DOCKER_COMPOSE start tak
sleep 10
### Checks if java is fully initialised
while :
do
	sleep 10
        printf $warning "Attempting to modify admin user with UserManager.jar:\n"
        # Note that ` is escaped through printf, so don't change it.
        $DOCKER_COMPOSE exec tak bash -c "cd /opt/tak/ && java -jar /opt/tak/utils/UserManager.jar usermod -A -p $(printf '%q' "$password") $user"
        usermod_status=$?
        echo "User modification status: $usermod_status"
	if [ $usermod_status -eq 0 ];
	then
                printf $warning "Attempting to modify admin cert with UserManager.jar:\n"
		$DOCKER_COMPOSE exec tak bash -c "cd /opt/tak/ && java -jar utils/UserManager.jar certmod -A certs/files/$user.pem"
                certmod_status=$?
                echo "Cert modification status: $certmod_status"
		if [ $certmod_status -eq 0 ];
		then
                        printf $warning "Attempting to upgrade schema with SchemaManager.jar:\n"
			$DOCKER_COMPOSE exec tak bash -c "java -jar /opt/tak/db-utils/SchemaManager.jar upgrade"
                        schema_upgrade_status=$?
                        echo "Schema upgrade status: $schema_upgrade_status"
			if [ $schema_upgrade_status -eq 0 ];
			then
                                # At this point TAK server setup is complete. Inform the user and break the loop.
                                printf $success "TAK server setup complete. Server is now running!\n\n"
				break
			else
                                # This would imply issues with the DB container or connectivity to it.
                                printf $danger "Schema upgrade failed, retrying in 10 seconds...\n"
				sleep 10
			fi
		else
                        printf $danger "Cert modification failed, retrying in 10 seconds...\n"
			sleep 10
		fi
	else
		printf $danger "No success. Will retry in 10 seconds. If this loop continues for more than a few minutes, run cleanup.sh and restart the process...\n"
	fi
done
### Post-installation message to the user including randomly generated passwords
current_dir=$(pwd)
printf $warning "---------LOGIN INSTRUCTIONS-------\n\n"
printf $warning "1. Import the $current_dir/tak/certs/files/$user.p12 certificate to your browser as per the README.md file\n"
printf $warning "2. Login at https://$IP:8443 or https://$cn:8443 with your admin account.\n\n"
printf $danger "---------PASSWORDS----------------\n\n"
printf $danger "Admin user name: $user\n" # Web interface username
printf $danger "Admin password: $password\n" # Web interface password randomly generated during setup
printf $danger "PostgreSQL password: $pgpassword\n" # PostgreSQL password randomly generated during setup
printf $danger "PKCS12 and JKS passwords for \`Let's Encrypt\` certificate: $pkcs12_password\n" # PKCS12 and JAVA keystore passwords randomly generated during set up
printf $danger "TAK Certificate Authority password: $capass\n\n" # TAK Certificate Authority password (also used for individual certificates created by this authority)
printf $warning "---------WARNINGS-----------------\n\n"
printf $warning "* MAKE NOTE OF YOUR PASSWORDS. THEY WON'T BE SHOWN AGAIN!\n"
printf $warning "* You have a database listening on TCP 5432 which requires a login. However, you should still block this port with a firewall\n"
printf $warning "* Following docker containers should automatically start with the Docker service from now on:\n"
docker container ls
