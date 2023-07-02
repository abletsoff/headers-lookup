#!/bin/bash

user_agent="Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0"

# last update: "2023-01-12 21:19:59"

disclosure_headers=("Host-Header" \
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
    "X-CF-Powered-By" \
    "X-CMS" \
    "X-Content-Encoded-By" \
    "X-Envoy-Upstream-Service-Time" \
    "X-Framework" \
    "X-Generated-By" \
    "X-Generator" \
    "X-Mod-Pagespeed" \
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
	"ASP.NET_SessionID_Fallback")

disclosure_items=('<meta name=\"generator\" content=\"Joomla! - Open Source Content Management\" />')

security_headers=("Strict-Transport-Security" \
   	"Content-Security-Policy" \
   	"X-Frame-Options" \
	"X-Content-Type-Options" \
	"Permissions-Policy" \
   	"Referrer-Policy")

ip_address_regex='([1-2]?\d{1,2}\.){3}[1-2]?\d{1,2}'

function f_cookies_analyzing () {
	http_response=$1
	e_disclosure_cookies=() # existing disclosure cookies 
	
	for cookie in "${disclosure_cookies[@]}"; do
		match=$(grep -i "^< Set-Cookie: ${cookie}" <<< $http_response)
		if [[ $match != "" ]]; then
			e_disclosure_cookies+=("$(cut -d " " -f 2-3 <<< $match)")
		fi
	done
	
	for cookie in "${e_disclosure_cookies[@]}"; do
		echo -e "${Red}Disclosure - ${cookie}${Color_Off}"
	done
}

function f_headers_analyzing () {
	http_response=$1
	e_disclosure_headers=() # existing disclosure headers
	e_security_headers=()	# existing security headers
	m_security_headers=()	# missed security headers

	for header in "${disclosure_headers[@]}"; do
		match=$(grep -i "^< ${header}:" <<< $http_response)
		if [[ $match != "" ]]; then
			e_disclosure_headers+=("$(cut -d " " -f 2- <<< $match)")
		fi
	done
	
	for header in "${security_headers[@]}"; do
		match=$(grep -i -m 1 "^< ${header}:" <<< $http_response)
		if [[ $match != "" ]]; then
			e_security_headers+=("$(cut -d " " -f 2- <<< $match)")
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

function f_body_analyzing () {
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

function f_http_parse () {
	
	http_response=$(curl -A "${user_agent}" --connect-timeout 5 -v $1 2>&1)
	
	if [[ $(grep "^curl: (28)" <<< $http_response) != "" ]]; then
		echo -e "Warning: Connection timeout"
		return 0
	elif [[ $(grep "^curl: (7)" <<< $http_response) != "" ]]; then
		echo -e "Warning: Failed to connect"
		return 0
	elif [[ $(grep "^curl: (56)" <<< $http_response) != "" ]]; then
		echo -e "Warning: Connection reset"
		return 0
	elif [[ $(grep "^curl: (60)" <<< $http_response) != "" ]]; then
        echo "Warning: (SSL certificate problem)"
	    http_response=$(curl -A "${user_agent}" --connect-timeout 5 -v -k $1 2>&1)
	elif [[ $(grep "^curl: (3)" <<< $http_response) != "" ]]; then
		echo -e "Error: URL bad/illegal format"
		return 0
	elif [[ $(grep "^curl: (52)" <<< $http_response) != "" ]]; then
		echo -e "Warning: Empty reply from server"
		return 0
	elif [[ $(grep "^curl: (35)" <<< $http_response) != "" ]]; then
		echo -e "Error: SSL connect error"
		return 0
	elif [[ $(grep "^curl: (6)" <<< $http_response) != "" ]]; then
		echo -e "Error: Could not resolve host"
		return 0
	fi
		
	response_code=$(grep -E "^< HTTP/" <<< $http_response)
	response_code=$(cut -d " " -f 2- <<< $response_code)
	echo -e "Response - ${response_code}"
	
	f_cookies_analyzing "$http_response"
	f_headers_analyzing "$http_response"
	f_body_analyzing "$http_response"
	
	if [[ $(grep -P '30[12378]' <<< $response_code) != "" ]]; then
		location=$(grep --ignore-case "< location" <<< $http_response)
		echo $location | cut -d " " -f 2-
		if [[ $follow_redirect == "True" ]]; then
			url=$(grep --only-matching -P "https?://\S*" <<< $location)
			f_http_parse "$url"
		fi
	fi
}

f_print_help () {
	echo -e "Usage: headers-lookup [options...] <url>\n" \
			 "-h\tdisplay this help and exit\n" \
			 "-c\tcolorized output\n" \
			 "-f\tfollow redirect"
}
while getopts "hcf" opt; do
	case $opt in
		h) 	f_print_help
			exit ;;
		c)
			Red='\033[0;91m'
			Yellow='\033[0;93m'
			Green='\033[0;92m'
			Color_Off='\033[0m';;
		f)	follow_redirect="True";;
		?) 	exit;;
	esac
done
shift $((OPTIND-1))

url=$1

if [[ $url != "" ]]; then
	f_http_parse "$url"
else
	f_print_help
fi
