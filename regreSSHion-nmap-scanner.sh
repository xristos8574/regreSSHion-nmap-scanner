nmap -sV -Pn -p22 -iL servers.txt | awk '/Nmap scan report/{ip=$5} /OpenSSH/ {
    if ($5 >= "8.5p1" && $5 < "9.8p1") {
        status = "Vulnerable to CVE-2024-6387"
    } else if ($5 >= "4.4p1" && $5 < "8.5p1") {
        status = "Not vulnerable to CVE-2024-6387 (patched for CVE-2006-5051)"
    } else if ($5 < "4.4p1") {
        status = "Vulnerable to regreSSHion (unless patched for CVE-2006-5051 and CVE-2008-4109)"
    }
    if (status) {
        print "Server: "ip"\t", "OpenSSH Version: "$5"\t", "Status: "status
        status = ""
    }
}'
