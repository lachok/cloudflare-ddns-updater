#!/bin/bash

set -e

if tty -s; then
  logger() {
    >&2 echo "$@"
  }
fi

###########################################
## Send a PushOver notification
###########################################
notify() {
  local message=$1
  curl -s \
       --form-string "token=$pushover_token" \
       --form-string "user=$pushover_user" \
       --form-string "message=$message" \
       https://api.pushover.net/1/messages.json
}

###########################################
## Check if we have a public IP
###########################################
get_public_ip_address() {
  ipv4_regex='([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\.([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\.([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\.([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])'
  ip=$(curl -s -4 https://cloudflare.com/cdn-cgi/trace | grep -E '^ip'); ret=$?
  if [[ ! $ret == 0 ]]; then # In the case that cloudflare failed to return an ip.
      # Attempt to get the ip from other websites.
      ip=$(curl -s https://api.ipify.org || curl -s https://ipv4.icanhazip.com)
  else
      # Extract just the ip from the ip line from cloudflare.
      ip=$(echo $ip | sed -E "s/^ip=($ipv4_regex)$/\1/")
  fi

  # Use regex to check for proper IPv4 format.
  if [[ ! $ip =~ ^$ipv4_regex$ ]]; then
      logger -s "DDNS Updater: Failed to find a valid IP."
      exit 2
  fi

  echo $ip
}

###########################################
## Check and set the proper auth header
###########################################
get_auth_header() {
  if [[ "${auth_method}" == "global" ]]; then
    echo "X-Auth-Key:"
  else
    echo "Authorization: Bearer"
  fi
}

###########################################
## Seek for the A record
###########################################
get_a_record() {
  local auth_header="$1"
  logger "DDNS Updater: Check Initiated"
  echo $(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$zone_identifier/dns_records?type=A&name=$record_name" \
                      -H "X-Auth-Email: $auth_email" \
                      -H "$auth_header $auth_key" \
                      -H "Content-Type: application/json")
}

###########################################
## Check if the domain has an A record
###########################################
verify_a_record() {
  local record=$1
  local ip=$2
  if [[ $record == *"\"count\":0"* ]]; then
    logger -s "DDNS Updater: Record does not exist, perhaps create one first? (${ip} for ${record_name})"
    exit 1
  fi
}

###########################################
## Check if the ip has changed
###########################################
ip_has_changed() {
  local record=$1
  local ip=$2
  old_ip=$(echo "$record" | sed -E 's/.*"content":"(([0-9]{1,3}\.){3}[0-9]{1,3})".*/\1/')
  # Compare if they're the same
  if [[ $ip == $old_ip ]]; then
    logger "DDNS Updater: IP ($ip) for ${record_name} has not changed."
    return 1
  fi
  return 0
}

###########################################
## Set the record identifier from result
###########################################
update_record_identifier() {
  local record=$1
  echo "$record" | sed -E 's/.*"id":"([A-Za-z0-9_]+)".*/\1/'
}

###########################################
## Change the IP@Cloudflare using the API
###########################################
update_record_in_cloudflare() {
  local record_identifier=$1
  local ip=$2
  local auth_header="$3"
  curl -s -X PATCH "https://api.cloudflare.com/client/v4/zones/$zone_identifier/dns_records/$record_identifier" \
                  -H "X-Auth-Email: $auth_email" \
                  -H "$auth_header $auth_key" \
                  -H "Content-Type: application/json" \
                  --data "{\"type\":\"A\",\"name\":\"$record_name\",\"content\":\"$ip\",\"ttl\":$ttl,\"proxied\":${proxy}}"
}

###########################################
## Report the status
###########################################
report_status() {
  local update=$1
  local ip=$2
  local record_identifier=$4

  case "$update" in
  *"\"success\":false"*)
    echo -e "DDNS Updater: $ip $record_name DDNS failed for $record_identifier ($ip). DUMPING RESULTS:\n$update" | logger -s 
    notify "$sitename DDNS Update Failed: '$record_name': '$record_identifier' ('$ip')."
    exit 1;;
  *)
    logger "DDNS Updater: $ip $record_name DDNS updated."
    notify "$sitename Updated: $record_name's new IP Address is $ip"
    exit 0;;
  esac
}


_whence=$(cd $(dirname $0); pwd)

# Load domains
for domain_config in $_whence/domains/*.json; do
  if [[ $(basename $domain_config) != "example.com.json" ]]; then
    logger "Reading config $(basename $domain_config)..."
    for s in $(cat $domain_config | jq -r "to_entries|map(\"\(.key)=\(.value|tostring)\")|.[]" ); do
      export $s
    done

    ip=$(get_public_ip_address)
    auth_header="$(get_auth_header)"
    record=$(get_a_record "$auth_header")

    verify_a_record "$record" "$ip"
    if ip_has_changed "$record" "$ip"; then
      record_identifier=$(update_record_identifier "$record")

      update=$(update_record_in_cloudflare "$record_identifier" "$ip" "$auth_header")
      report_status "$update" "$ip" "$record_identifier"
    fi
  fi
done