#!/bin/bash
# dlb_name/client-cert/cert_name.pem
# dlb_name/server-cert/ssl-public.pem
# dlb_name/server-cert/ssl-private.pem
#
signv4js="`cat javascript_util.js`"
aws4js="`cat aws4.js`"
lrujs="`cat lru.js`"

cd /tmp

echo "$signv4js" > javascript_util.js
echo "$aws4js" > aws4.js
echo "$lrujs" > lru.js

HEADERS="$(mktemp)"
# Get the lambda invocation event
EVENT_DATA=$(curl -sS -LD "$HEADERS" -X GET "http://${AWS_LAMBDA_RUNTIME_API}/2018-06-01/runtime/invocation/next")

# Extract request ID by scraping response headers received above
REQUEST_ID=$(grep -Fi Lambda-Runtime-Aws-Request-Id "$HEADERS" | tr -d '[:space:]' | cut -d: -f2)

creds="{\"accessKeyId\": \"${AWS_ACCESS_KEY}\" , \"secretAccessKey\" : \"${AWS_SECRET_KEY}\"}"

function get_secret {
  payload='{\"SecretId\": \"'"${1}"'\"}'
  opts="{
        \"host\": \"secretsmanager.${AWS_REGION}.amazonaws.com\", 
        \"path\": \"/\", 
        \"service\": \"secretsmanager\", 
        \"region\": \"${AWS_REGION}\",
        \"headers\": {
                \"Content-Type\": \"application/x-amz-json-1.1\",
                \"X-Amz-Target\": \"secretsmanager.GetSecretValue\"
            },
        \"body\": \"$payload\"
    }"
  node javascript_util "sign" "$creds" "$opts"
  auth=$(sed -n "1 p" tempFile)
  date=$(sed -n "2 p" tempFile)
  rm tempFile
  temp_xml_file="tempFile"
  curl --request POST "https://secretsmanager.${AWS_REGION}.amazonaws.com" \
    -H "Authorization: ${auth}" \
    -H "x-amz-date: ${date}" \
    -H "content-type: application/x-amz-json-1.1" \
    -H "x-amz-target: secretsmanager.GetSecretValue" \
    --data-raw '{"SecretId": "'"${1}"'"}' \
    -k -sS -o ${temp_xml_file}

  node javascript_util "parse_secret"
  secret="`cat tempFile`"
}

# This function will list all the secrets from Secrets Manager and store them in certList file
function list_secrets {
  payload='{}'
  data_raw='{}'

  if [[ $# -eq 1 ]]; then
    payload='{\"NextToken\": \"'"${1}"'\"}'
    data_raw='{"NextToken": "'"${1}"'"}'
  fi
  
  opts="{
        \"host\": \"secretsmanager.${AWS_REGION}.amazonaws.com\", 
        \"path\": \"/\", 
        \"service\": \"secretsmanager\", 
        \"region\": \"${AWS_REGION}\",
        \"headers\": {
                \"Content-Type\": \"application/x-amz-json-1.1\",
                \"X-Amz-Target\": \"secretsmanager.ListSecrets\"
            },
        \"body\": \"$payload\"
    }"
    node javascript_util "sign" "$creds" "$opts"
    auth=$(sed -n "1 p" tempFile)
    date=$(sed -n "2 p" tempFile)
    rm tempFile
    temp_xml_file="tempFile"

    curl --request POST "https://secretsmanager.${AWS_REGION}.amazonaws.com" \
      -H "Authorization: ${auth}" \
      -H "x-amz-date: ${date}" \
      -H "content-type: application/x-amz-json-1.1" \
      -H "x-amz-target: secretsmanager.ListSecrets" \
      --data-raw "`echo $data_raw`" \
      -k -sS -o ${temp_xml_file}
    
    if [[ "`cat tempFile`" == *"NextToken"* ]]; then
      node javascript_util "list_certs" "${TIME_WINDOW_IN_HRS}"
      next_token=$(sed -n "1 p" nextToken)
      next_token="${next_token//[$'\t\r\n']}"
      rm nextToken
      rm tempFile
      list_secrets "$next_token"
    else
      node javascript_util "list_certs" "${TIME_WINDOW_IN_HRS}"
      rm tempFile
    fi
}

# This function will list the secrets which are not updated within 24 hrs on Secrets Manager and store them in certList file
function list_old_secrets {
  payload='{}'
  data_raw='{}'

  if [[ $# -eq 1 ]]; then
    payload='{\"NextToken\": \"'"${1}"'\"}'
    data_raw='{"NextToken": "'"${1}"'"}'
  fi
  
  opts="{
        \"host\": \"secretsmanager.${AWS_REGION}.amazonaws.com\", 
        \"path\": \"/\", 
        \"service\": \"secretsmanager\", 
        \"region\": \"${AWS_REGION}\",
        \"headers\": {
                \"Content-Type\": \"application/x-amz-json-1.1\",
                \"X-Amz-Target\": \"secretsmanager.ListSecrets\"
            },
        \"body\": \"$payload\"
    }"
    node javascript_util "sign" "$creds" "$opts"
    auth=$(sed -n "1 p" tempFile)
    date=$(sed -n "2 p" tempFile)
    rm tempFile
    temp_xml_file="tempFile"

    curl --request POST "https://secretsmanager.${AWS_REGION}.amazonaws.com" \
      -H "Authorization: ${auth}" \
      -H "x-amz-date: ${date}" \
      -H "content-type: application/x-amz-json-1.1" \
      -H "x-amz-target: secretsmanager.ListSecrets" \
      --data-raw "`echo $data_raw`" \
      -k -sS -o ${temp_xml_file}
    
    if [[ "`cat tempFile`" == *"NextToken"* ]]; then
      node javascript_util "list_certs" "${TIME_WINDOW_IN_HRS}"
      next_token=$(sed -n "1 p" nextToken)
      next_token="${next_token//[$'\t\r\n']}"
      rm nextToken
      rm tempFile
      list_secrets "$next_token"
    else
      node javascript_util "restore_old_cert" "${TIME_WINDOW_IN_HRS}"
      rm tempFile
    fi
}

function handle_error {
	echo "${1}"
  rm -r $dir1
  rm -r $dir2
  rm dlbList
  rm certList
  echo "DLB will be restored with older certificates.."
  list_old_secrets
  update_cloudhub_dlb_cert
  echo "DLB is restored with old certificates."
  alert_exp_cert
	curl -sS -X POST "http://${AWS_LAMBDA_RUNTIME_API}/2018-06-01/runtime/invocation/$REQUEST_ID/response" -d "${1}"
  exit 1
}

function update_cloudhub_dlb_cert {
  total_dlbs_to_update=$(wc -l dlbList | awk '{ print $1 }')
  for (( dlbcount=1; dlbcount<=$total_dlbs_to_update; dlbcount++ ))
  do 
    dlbName=$(sed -n "$dlbcount p" dlbList)
    dlbName="${dlbName//[$'\t\r\n']}"
    dir1="ca_certs_$dlbName"
    dir2="ssl_certs_$dlbName"
    cert_file_name="public.pem"
    private_key_file_name="private.pem"
    merged_certs_name="bundle.pem"
    ca_cert_present=false
    ssl_cert_present=false
    ssl_private_key_present=false
    mkdir $dir1
    mkdir $dir2
    total_certs=$(wc -l certList | awk '{ print $1 }')
    for (( j=1; j<=$total_certs; j++ ))
    do 
      cur_cert=$(sed -n "$j p" certList)
      cur_cert="${cur_cert//[$'\t\r\n']}"     # removing \t \r \n characters

      if [[ "`echo $cur_cert`" == *"$dlbName"* ]]; then
        if [[ "`echo $cur_cert`" == *"client-cert"* ]]; then
          get_secret "$cur_cert"
          # Checking if certificate is valid by trying to check its expiry date
          node javascript_util "days_to_expire"
          days_to_expire=$(sed -n "1 p" daysToExpire)
          days_to_expire="${days_to_expire//[$'\t\r\n']}"
          rm daysToExpire
          if [[ $days_to_expire == "Invalid" ]]; then
            echo "The client certificate $cur_cert is invalid and will not be added in the client certificates bundle"
            continue
          fi
          cp tempFile "$dir1/client$j"
          rm tempFile
          ca_cert_present=true
        elif [[ "`echo $cur_cert`" == *"server-cert"* && "`echo $cur_cert`" == *"public"* ]]; then
          get_secret "$cur_cert"
          cp tempFile "$dir2/$cert_file_name"
          rm tempFile
          ssl_cert_present=true
        elif [[ "`echo $cur_cert`" == *"server-cert"* && "`echo $cur_cert`" == *"private"* ]]; then
          get_secret "$cur_cert"
          cp tempFile "$dir2/$private_key_file_name"
          rm tempFile
          ssl_private_key_present=true
        fi
      fi
      
    done
    awk '{print $0}' $dir1/* > $merged_certs_name
    rm $dir1/*
    mv $merged_certs_name $dir1/$merged_certs_name
    if [[ $ssl_cert_present == false ]]; then
      echo "SSL public certificate not found for DLB: $dlbName"
      continue
    fi
    if [[ $ssl_private_key_present == false ]]; then
      echo "SSL private key not found for DLB: $dlbName"
      continue
    fi
    
    # Get common name of the certificate
    {
      cert_name=$(openssl x509 -noout -subject -in $dir2/$cert_file_name) &&
      cert_name=$(echo "${cert_name##*=}" | xargs)
    } || {
      echo "Error in getting common name of the ssl certificate for DLB: ${dlbName}. Skipping this DLB.."
      continue
    }
    
    # Replace the certificate

    # Setting dummy cert as default cert
    dummy_cert_name='dummy'
    echo "Setting ${dummy_cert_name} as default certificate..."
    i=0
    error_occured=false
    while [ $i -lt 3 ]
    do
      if [[ $i -gt 0 ]]; then
        echo "Retry attempt ${i}..."
      fi
      { 
        anypoint-cli-v4 cloudhub:load-balancer:ssl-endpoint:setDefault $dlbName $dummy_cert_name &&
        echo "${dummy_cert_name} has been set as default certificate successfully!" &&
        error_occured=false &&
        break
      } || { 
        ((i++))
          error_occured=true
        }
    done

    if [[ $error_occured == true ]]; then
        echo "Could not set ${dummy_cert_name} as default certificate due to some error. Continuing the process.."
    fi

    # Deleting the ssl cert
    echo "Deleting cert ${cert_name}..."
    i=0
    error_occured=false
    while [ $i -lt 3 ]
    do
      if [[ $i -gt 0 ]]; then
        echo "Retry attempt ${i}..."
      fi
      { 
        anypoint-cli-v4 cloudhub:load-balancer:ssl-endpoint:remove ${dlbName} ${cert_name} &&
        echo "Certificate ${cert_name} deleted successfully!" &&
        error_occured=false &&
        break
      } || { 
        ((i++))
          error_occured=true
        }
    done

    if [[ $error_occured == true ]]; then
        echo "Some error occured while deleting the certificate ${cert_name}. Continuing the process.."
    fi

    # Uploading the updated cert
    echo "Uploading updated cert ${cert_name}..."
    i=0
    error_occured=false
    while [ $i -lt 3 ]
    do
      if [[ $i -gt 0 ]]; then
        echo "Retry attempt ${i}..."
      fi
      { 
        anypoint-cli-v4 cloudhub:load-balancer:ssl-endpoint:add --clientCertificate "$dir1/${merged_certs_name}" --verificationMode on $dlbName "$dir2/${cert_file_name}" "$dir2/${private_key_file_name}" &&
        echo "Certificate ${cert_name} added successfully!" &&
        error_occured=false &&
        break
      } || { 
          ((i++))
          error_occured=true
        }
    done

    if [[ $error_occured == true ]]; then
        handle_error "ERROR: Some error occured while adding the certificate ${cert_name}."
        return
    fi

    # Setting the updated cert as default
    echo "Setting ${cert_name} as default certificate..."
    i=0
    error_occured=false
    while [ $i -lt 3 ]
    do
      if [[ $i -gt 0 ]]; then
        echo "Retry attempt ${i}..."
      fi
      { 
        anypoint-cli-v4 cloudhub:load-balancer:ssl-endpoint:setDefault $dlbName $cert_name &&
        echo "${cert_name} has been set as default certificate successfully!" &&
        error_occured=false &&
        break
      } || { 
        ((i++))
          error_occured=true
        }
    done

    if [[ $error_occured == true ]]; then
        echo "Could not set ${cert_name} as default certificate due to some error"
    fi

    echo "Certificate $cert_name updated successfully!"
    
    rm -r $dir1
    rm -r $dir2
  done
  rm dlbList
  rm certList
}

function sns_alert {
  opts="{
        \"host\": \"sns.${AWS_REGION}.amazonaws.com\", 
        \"path\": \"/?Action=Publish&TopicArn=${AWS_SNS_TOPIC_ARN}&Message=${2}&Subject=${1}\", 
        \"service\": \"sns\", 
        \"region\": \"${AWS_REGION}\",
        \"headers\": {
                \"Content-Type\": \"application/x-amz-json-1.1\"
            },
        \"body\": \"\"
    }"
  node javascript_util "sign" "$creds" "$opts"
  auth=$(sed -n "1 p" tempFile)
  date=$(sed -n "2 p" tempFile)
  rm tempFile
  temp_xml_file="tempFile"
  curl --get "https://sns.${AWS_REGION}.amazonaws.com/" \
    --data-urlencode "Action=Publish" \
    --data-urlencode "TopicArn=${AWS_SNS_TOPIC_ARN}" \
    --data-urlencode "Message=${2}" \
    --data-urlencode "Subject=${1}" \
    -H "Authorization: ${auth}" \
    -H "x-amz-date: ${date}" \
    -H "content-type: application/x-amz-json-1.1" \
    --data-raw "" \
    -k -sS > /dev/null
}

function alert_exp_cert {
  list_secrets
  echo "Checking for expired and soon expiring certificates..."
  total_certs=$(wc -l certList | awk '{ print $1 }')
  x=1;y=1;z=1
  invalid_cert=false; expired_cert=false; soon_expiring_cert=false
  list_of_invalid_certs="";list_of_expired_certs="";list_of_soon_expiring_certs=""
  for (( j=1; j<=$total_certs; j++ ))
    do 
      cur_cert=$(sed -n "$j p" certList)
      cur_cert="${cur_cert//[$'\t\r\n']}"
      if [[ "`echo $cur_cert`" == *"client-cert"* || ( "`echo $cur_cert`" == *"server-cert"* && "`echo $cur_cert`" == *"public"* ) ]]; then
        get_secret "$cur_cert"
        node javascript_util "days_to_expire"
        days_to_expire=$(sed -n "1 p" daysToExpire)
        days_to_expire="${days_to_expire//[$'\t\r\n']}"
        if [[ $days_to_expire == "Invalid" ]]; then
          echo "Invalid certificate $cur_cert"
          invalid_cert=true
          list_of_invalid_certs="$list_of_invalid_certs$x. $cur_cert "
          ((x++))
        elif [[ $days_to_expire -lt 0 ]]; then
          echo "certificate $cur_cert expired$days_to_expire days ago"
          expired_cert=true
          list_of_expired_certs="$list_of_expired_certs$y. $cur_cert "
          ((y++))
        elif [[ $days_to_expire -le 30 ]]; then
          msg="Certificate $cur_cert is going to expire soon in $days_to_expire days."
          echo $msg
          soon_expiring_cert=true
          list_of_soon_expiring_certs="$list_of_soon_expiring_certs$z. $msg "
          ((z++))
        else
          echo "days before expiry for certificate $cur_cert: $days_to_expire"
        fi
        rm daysToExpire
        rm tempFile
      fi
    done

    if [[ ($x -gt 1) || ($y -gt 1) || ($z -gt 1) ]]; then
      email_message=""
      if [[ $x -gt 1 ]]; then
        email_message="*Following certificate(s) are invalid: $list_of_invalid_certs  "
      fi
      if [[ $y -gt 1 ]]; then
        email_message="$email_message *Following certificate(s) are expired: $list_of_expired_certs  "
      fi
      if [[ $z -gt 1 ]]; then
        email_message="$email_message *Following certificate(s) are expiring soon: $list_of_soon_expiring_certs"
      fi
      echo "$email_message"
      sns_alert "ALERT: Update DLB certificates on Secret Manager" "$email_message"
    else
      echo "No certificate is expired or going to expire in next 30 days"
    fi
    rm certList
    rm dlbList
    rm isCertUpdated
}

###############################################################################
invoke functions
list_secrets
is_cert_updated=$(sed -n "1 p" isCertUpdated)
is_cert_updated="${is_cert_updated//[$'\t\r\n']}"
rm isCertUpdated
if [[ $is_cert_updated == true ]]; then
  update_cloudhub_dlb_cert
else
  echo "No certificate updated in last ${TIME_WINDOW_IN_HRS} hrs"
  rm certList
fi
alert_exp_cert
################################################################################

# Send the response
curl -sS -X POST "http://${AWS_LAMBDA_RUNTIME_API}/2018-06-01/runtime/invocation/$REQUEST_ID/response" -d "Lambda function completed execution."