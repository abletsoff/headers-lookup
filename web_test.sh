#!/bin/bash

user_agent="Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0"

disclosure_headers=('Server' 'Liferay-Portal' 'X-Turbo-Charged-By' 'X-Powered-By' \
		'X-Server-Powered-By' 'X-Powered-CMS' 'SourceMap or X-SourceMap' 'X-AspNetMvc-Version' \
		'X-AspNet-Version' 'X-SourceFiles' 'X-Redirect-By' 'X-Generator' 'X-Generated-By' 'X-CMS')

security_headers=('Strict-Transport-Security' 'Content-Security-Policy' 'X-Frame-Options' \
		'X-Content-Type-Options' 'Permissions-Policy' 'Referrer-Policy')
ip_address_regex='([1-2]?\d{1,2}\.){3}[1-2]?\d{1,2}'

Red='\033[0;91m'
Yellow='\033[0;93m'
Green='\033[0;92m'
Color_Off='\033[0m' 

function f_dns_resolve () {

	domain=$1
   	ip_address=$(grep -P $ip_address_regex <<< $domain)
	
	if [[ $ip_address == "" ]]; then
   		resolve=$(dig +short $domain | head -n 1)	
    	if [[ $resolve == "" ]]; then
    	    resolve="unresolved"
		fi
		echo -e "$domain - $resolve"
	else
		echo -e "$domain"
	fi
}

function f_http_parse () {
	
	e_disclosure_headers=() # existing disclosure headers
	e_security_headers=()	# existing security headers
	m_security_headers=()	# missed security headers

	http_response=$(curl -A "${user_agent}" --connect-timeout 5 -v $1 2>&1)
	
	if [[ $(grep "^curl: (28)" <<< $http_response) != "" ]]; then
		echo -e "\t${Red}Connection timeout${Color_Off}"
		return 0
	elif [[ $(grep "^curl: (7)" <<< $http_response) != "" ]]; then
		echo -e "\t${Red}Failed to connect${Color_Off}"
		return 0
	elif [[ $(grep "^curl: (56)" <<< $http_response) != "" ]]; then
		echo -e "\t${Red}Connection reset${Color_Off}"
		return 0
	elif [[ $(grep "^curl: (60)" <<< $http_response) != "" ]]; then
		echo -e "\t${Red}SSL certificate problem${Color_Off}"
		return 0
	fi
		
	response_code=$(grep -E "^< HTTP/" <<< $http_response)
	response_code=$(cut -d " " -f 3- <<< $response_code)
	echo -e "\t${response_code}"
		
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
		echo -e "\t${Red}${header}${Color_Off}"
	done
	
	if [[ $(grep '200' <<< $response_code) != "" ]]; then
		for header in "${e_security_headers[@]}"; do
			echo -e -n "\t${Green}$(cut -d " " -f 1-4 <<< $header)${Color_Off}"
			if (( $(tr -cd ' ' <<< $header | wc -c) < 4 )); then
				echo ""
			else
				echo -e "${Green} ...${Color_Off}"
			fi
		done
		
		for header in "${m_security_headers[@]}"; do
			echo -e "\t${Yellow}${header} - missing${Color_Off}"
		done
	fi
}

function f_resources_check () {
	domain=$1

    f_dns_resolve $domain
	if [[ $resolve != 'unresolved' ]]; then
   		echo -e -n '\tHTTP: '
		f_http_parse $domain
		echo -e -n '\tHTTPS: '
   		f_http_parse "https://${domain}"
		echo ""
	fi
}

param=$1

if [[ $param != "" ]]; then
	domain=("${param}")
else
	domain=("example.com")
fi

www_subdomain=$(grep "^www\." <<< $domain)

f_resources_check $domain

if [[ $ip_address == "" ]] && [[ $www_subdomain == "" ]]; then
	f_resources_check "www.${domain}"
fi
