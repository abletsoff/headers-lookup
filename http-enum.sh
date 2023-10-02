#!/bin/bash

user_agent="Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0"
err_file="/tmp/http-enum-stderr"

disclosure_headers=("\$wsep" \
    "Host-Header" \
    "K-Proxy-Request" \
    "Liferay-Portal" \
    "Pega-Host" \
    "Powered-By" \
    "Product" \
    "Server" \
    "SourceMap" \
    "X-AspNet-Version" \
    "X-AspNetMvc-Version" \
    "X-Atmosphere-error" \
    "X-Atmosphere-first-request" \
    "X-Atmosphere-tracking-id" \
    "X-B3-ParentSpanId" \
    "X-B3-Sampled" \
    "X-B3-SpanId" \
    "X-B3-TraceId" \
    "X-CF-Powered-By" \
    "X-CMS" \
    "X-Content-Encoded-By" \
    "X-Envoy-Attempt-Count" \
    "X-Envoy-External-Address" \
    "X-Envoy-Internal" \
    "X-Envoy-Original-Dst-Host" \
    "X-Envoy-Upstream-Service-Time" \
    "X-Framework" \
    "X-Generated-By" \
    "X-Generator" \
    "X-Mod-Pagespeed" \
    "X-Nextjs-Cache" \
    "X-Nextjs-Matched-Path" \
    "X-Nextjs-Page" \
    "X-Nextjs-Redirect" \
    "X-Old-Content-Length" \
    "X-Page-Speed" \
    "X-Php-Version" \
    "X-Powered-By" \
    "X-Powered-By-Plesk" \
    "X-Powered-CMS" \
    "X-Redirect-By" \
    "X-Server-Powered-By" \
    "X-SourceFiles" \
    "X-SourceMap" \
    "X-Turbo-Charged-By" \
    "X-Varnish-Backend" \
    "X-Varnish-Server")

disclosure_cookies=("PHPSESSID" \
	"ASP.NET_SessionID" \
	"ASP.NET_SessionID_Fallback" \
    "BITRIX_SM_GUEST_ID" \
    "BITRIX_SM_LAST_VISIT" \
    "BITRIX_SM_BANNERS")

disclosure_items=('<meta name=\"generator\" content=\"Joomla! - Open Source Content Management\" />')

security_headers=("Strict-Transport-Security" \
   	"Content-Security-Policy" \
   	"X-Frame-Options" \
	"X-Content-Type-Options" \
	"Permissions-Policy" \
   	"Referrer-Policy")

ip_address_regex='([1-2]?\d{1,2}\.){3}[1-2]?\d{1,2}'

f_cookies_analyzing () {
	http_response=$1
	e_disclosure_cookies=()

    header_cookies=$(grep -i -P "^Set-Cookie: " <<< $http_response)

    for header_cookie in "${header_cookies[@]}"; do
        disclosure_found='false'
        for disclosure_cookie in "${disclosure_cookies[@]}"; do
            if [[ $(echo "$header_cookie" | grep -i "$disclosure_cookie") != '' ]]; then
			    e_disclosure_cookies+=("$disclosure_cookie")
                disclosure_found='true'
            fi
        done
    done
	
	for cookie in "${e_disclosure_cookies[@]}"; do
		echo -e "${Red}Disclosure - set-cookie: ${cookie}${Color_Off}"
	done
}

f_headers_analyzing () {
	http_response=$1
	e_disclosure_headers=() # existing disclosure headers
	e_security_headers=()	# existing security headers
	m_security_headers=()	# missed security headers

	for header in "${disclosure_headers[@]}"; do
		match=$(grep -i "^${header}:" <<< $http_response)
		if [[ $match != "" ]]; then
			e_disclosure_headers+=("$(cut -d " " -f 1- <<< $match)")
		fi
	done
	
	for header in "${security_headers[@]}"; do
		match=$(grep -i -m 1 "^${header}:" <<< $http_response)
		if [[ $match != "" ]]; then
			e_security_headers+=("$(cut -d " " -f 1- <<< $match)")
		else
			m_security_headers+=("${header}")	
		fi
	done
	
	for header in "${e_disclosure_headers[@]}"; do
		echo -e "${Red}Disclosure - ${header}${Color_Off}"
	done
	
	if [[ $(grep -P '3\d\d' <<< $response_code) == "" ]]; then
		for header in "${m_security_headers[@]}"; do
			echo -e "${Yellow}Missing - ${header}${Color_Off}"
		done
		
		for header in "${e_security_headers[@]}"; do
			echo -e -n "${Green}Existing - $(cut -d " " -f 1-4 <<< $header)${Color_Off}"
			if (( $(tr -cd ' ' <<< $header | wc -c) < 4 )); then
				echo ""
			else
				echo -e "${Green} ...${Color_Off}"
			fi
		done
	fi
}

f_body_analyzing () {
	http_response=$1
	e_disclosure_items=() # existing disclosure items
	
	for item in "${disclosure_items[@]}"; do
		match=$(grep -o "${item}" <<< $http_response)
		if [[ $match != "" ]]; then
			e_disclosure_items+=("$match")
		fi
	done
	
	if [ ! ${#e_disclosure_items[@]} -eq 0 ]; then
		echo "HTTP body disclosure:"
	fi
	
	count=1	
	for item in "${e_disclosure_items[@]}"; do
		echo -e "${Red}${count}) ${item}${Color_Off}"
		count=$((count+1))
	done
}

f_http_parse () {
    first_output=$1
    url=$2

    if [[ $first_output == 'false' ]]; then
        echo ''
    fi
    echo "URL: $url"

    http_response=$(curl -sS -A "${user_agent}" --connect-timeout 5 -i "$url" \
        2>$err_file | tr '\0' '\n')

    if  [[ $(grep "curl: (60)" $err_file) != "" ]]; then
        echo "Warning: (SSL certificate problem)"
        http_response=$(curl -sS -k -A "${user_agent}" --connect-timeout 5 -i "$url" \
         2>$err_file | tr '\0' '\n')
    fi

    if  [[ $(grep "curl: (" $err_file) != "" ]]; then
        cat $err_file
        return 1
    fi
	
	response_code=$(grep -E "^HTTP/" <<< $http_response)
	echo "Response - ${response_code}"
	
	f_cookies_analyzing "$http_response"
	f_headers_analyzing "$http_response"
	f_body_analyzing "$http_response"
	
	if [[ $(grep -P '30[12378]' <<< $response_code) != "" ]]; then
		location=$(grep --ignore-case "location" <<< $http_response)
		echo "$location"
		if [[ $follow_redirect == "True" ]]; then
			url=$(grep --only-matching -P "https?://\S*" <<< $location)
			f_http_parse "false" "$url"
		fi
	fi
}


f_ip_request () {
    scheme_host=$(echo "$url" | grep -o -P "(https?:\/\/)?[A-Z,a-z,1-9,\.]+" \
        | head -n 1)
    
    if [[ $(echo "$scheme_host" | grep ":") != '' ]]; then
        host=$(echo $scheme_host | cut -d ":" -f2 | sed "s/\///g")
    else
       host=$scheme_host
    fi

    resolve=($(dig +short $host | grep -P "$ip_address_regex"))
    for ip in ${resolve[@]}; do
        url=$(echo "$url" | sed "s/$host/$ip/g")
        f_http_parse "false" "$url"
    done
}

f_print_help () {
	echo -e "Usage: headers-lookup [options...] <url>\n" \
			"-h\tdisplay this help and exit\n" \
			"-c\tcolorized output\n" \
			"-f\tfollow redirect\n"
            "-i\tIP address in hostname(e.g. Host: 8.8.8.8)"
}
while getopts "hcfi" opt; do
	case $opt in
		h) 	f_print_help
			exit ;;
		c)
			Red='\033[0;91m'
			Yellow='\033[0;93m'
			Green='\033[0;92m'
			Color_Off='\033[0m';;
		f)	follow_redirect="True";;
		i)	ip_request="True";;
		?) 	exit;;
	esac
done
shift $((OPTIND-1))

url=$1

if [[ $url != "" ]]; then
	f_http_parse "true" "$url"
    if [[ $ip_request = "True" ]]; then
        f_ip_request
    fi
else
	f_print_help
fi
