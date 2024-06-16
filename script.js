//I log a lot to the console, this will clear it with each refresh.
console.clear()

//gathering buttons and text fields
var submit = document.getElementById("submit");

var zenOut = document.getElementById("zenOut");
var zenMarkupButton = document.getElementById("zenMarkupButton");

var zen_ticket_output_text = document.getElementById("zenTicketOutP");
var zenTicketButton = document.getElementById("zenTicketButton");

var summaryText = document.getElementById("summary");
var summaryButton = document.getElementById("summaryID");

var ticketOut = document.getElementById("tick");
var VPNSummaryButton = document.getElementById("VPNSummaryID");

var MalSummaryButton = document.getElementById("MalSummaryID");

var UFNPCSummaryButton = document.getElementById("UFNPCSummaryID");

var I2CSummaryButton = document.getElementById("I2CSummaryID");

var PFSummaryButton = document.getElementById("PFSummaryID");

var BruteForceButton = document.getElementById("BFID");

var warning = document.getElementById("warningID");

var data;

//testing to use interactive web console to query objs
//var data = JSON.parse(document.getElementById("input").value);

//ticket listeners
submit.addEventListener("click", function(){
    run()
})

//buttons to copy to clipboard
zenMarkupButton.addEventListener("click", function(){
    navigator.clipboard.writeText(zenOut.value);
})

zenTicketButton.addEventListener("click", function(){
  copyToClip(zen_ticket_output_text.innerHTML);
})

summaryButton.addEventListener("click", function(){
  copyToClip(summaryText.innerHTML);
})

BruteForceButton.addEventListener("click", function(){
    run();

    warning.innerHTML = "PLEASE LOOK OVER THE TICKET AND MAKE SURE EVERYTHING MAKES SENSE";

    let source_IP = findSrcIP(data)
    let target_user = findDestUser(data)
    let source_host = findDestHost(data)

    ticketOut.innerHTML = "alerted to the IP address " + source_IP + " as a potential threat in your environment. " +
    ".<br><br><br><b>INVESTIGATION FINDINGS:</b><br>Our team alerted to the IP address " + source_IP
    + " attempting to remotely access the user " + target_user + " on the host " + source_host + ". During the investigation, the IP address was\
    found to be malicious and is known for brute force attempts. The IP address failed all the attempts to authenticate into the account " + target_user +
    " and no other indicators of compromise are present. We are reaching out to bring awareness to this potential threat. Thank you.\
    <br><br><b>RECOMMENDATION(S)/ACTION TAKEN:</b><br>\
    1. Our team recommends blocking this IP address.<br>\
    2. Our team recommends disabling RDP on this host.<br>\
    3. Our team recommends ensuring all hosts have the most up-to-date antivirus.<br><br>\
    \
     <b>REFERENCES/RESOURCES:</b><br>\
     https://attack.mitre.org/techniques/T1110/<br>\
    https://www.virustotal.com/gui/ip-address/"+ source_IP +"<br><br>\
     \
     <b>======================<br>ADDITIONAL INFORMATION:<br>======================</b><br>"  + zen_ticket_output_text.innerHTML +
         "If you have any questions or concerns, please contact the Security Operations Center (SOC).";
    
    copyToClip(ticketOut.innerHTML);
})

PFSummaryButton.addEventListener("click", function(){
    run();

    password_file_path = findPasswordFile(data);
    passwordFile = password_file_path.split("\\")[password_file_path.split("\\").length - 1];

    warning.innerHTML = "PLEASE LOOK OVER THE TICKET AND MAKE SURE EVERYTHING MAKES SENSE";

    ticketOut.innerHTML = "alerted to a plaintext password or credential file: " + passwordFile + " on the host "+ findSrcHost(data) +
    ".<br><br><br><b>INVESTIGATION FINDINGS:</b><br>Our team alerted to the file " + passwordFile
    + " from the user " + findSrcUser(data) + " on the host " + findSrcHost(data) + ". This file appears to contain passwords and credentials in\
    plaintext. Plaintext files lack encryption, or password protection making sensitive information easily readable and accessible to users \
    and user-level programs. Additionally, these files are often targeted and abused by credential stealing malware for data exfiltration and\
    credential based attacks. Storing files in this way is bad practice and not recommended. Please review remediation steps. Thank you.\
    <br><br><b>RECOMMENDATION(S)/ACTION TAKEN:</b><br>\
    1. Our team recommends securely deleting the file.<br>\
    2. Our team recommends using a secure password manager.<br>\
    3. Our team recommends scanning the affected host for malware.<br>\
    4. Our team recommends ensuring all hosts have the most up-to-date antivirus.<br><br>\
    \
     <b>REFERENCES/RESOURCES:</b><br>\
     https://attack.mitre.org/techniques/T1589/001/<br>\
     https://owasp.org/www-community/vulnerabilities/Password_Plaintext_Storage<br><br>\
     \
     <b>======================<br>ADDITIONAL INFORMATION:<br>======================</b><br>" + zen_ticket_output_text.innerHTML.split("<br><br>")[0] +
     "<br><br><b>File:</b> " + passwordFile +
     "<br><b>File Path:</b> " + password_file_path +
     "<br><br><b>Command Line:</b> " + findCommandLine(data) +
     "<br><br>If you have any questions or concerns, please contact the Security Operations Center (SOC).";
copyToClip(ticketOut.innerHTML);

})


I2CSummaryButton.addEventListener("click", function(){

    let inputText = document.getElementById("input").value;
    let inputArr = inputText.split("\n");
    let srcUser = "";
    let ipAddrs = [];
    let countries = ["Russia", "North Korea", "China", "Iran", "India", "Brazil", "Venezuela"];
    let ownedBy = [];

    let pattern = /\b([0-9]{1,3}\.){3}[0-9]{1,3}\b/g


    for(let i=0; i<inputArr.length; i++){
        let line = inputArr[i];
        if(pattern.test(line)){

            ipAddr = line.match(pattern)[0];

            if(!ipAddrs.includes(ipAddr)){
                ipAddrs.push(ipAddr);
            }
            
            if(line.includes("owned by")){
                ownedBy.push(line);
            }
        }

        if(line.includes("with user")){
            srcUser = line.split(" ")[0];
        }
    }

    ticketBody = "<br><br><br><b>INVESTIGATION FINDINGS:</b><br>Our team alerted to the user "+srcUser+" authenticating from two countries in a short period of time. The user "+srcUser+
    " authenticated from the IP address " + ipAddrs[0] + " and the IP address " + ipAddrs[1] + ". The IP address " + ownedBy[0] +" and the IP address " + ownedBy[1] + ". Neither of these \
    IP addresses were found to be malicious. ";

    for(let i=0; i<ownedBy.length; i++){
        for(let j=0; j<countries.length; j++){
            if(ownedBy[i].includes(countries[j])){
                ticketBody += "The country " + countries[j] + " is known to be a high risk country. "
            }
        }
    }

    ticketBody += "The time-span and distance indicates there are multiple users authenticating or the user is utilizing a VPN. We are reaching out to confirm this is expected and permissible behavior. Thank you!<br>"


    ticketOut.innerHTML = "alerted to the user " + srcUser + " authenticating from two countries in a short period of time.<br>" + ticketBody + 
    "<br><br><b>RECOMMENDATION(S)/ACTION TAKEN:</b><br>\
        1. Our team recommends verifying the activity with the affected user.<br>\
        2. Our team recommends blocking the affected IP address.<br>\
        3. Our team recommends revoking the user's MFA and forcibly logging the user out.<br><br>\
         <b>REFERENCES/RESOURCES:</b><br>\
         https://www.virustotal.com/gui/search/" + ipAddrs[0] + "<br>\
         https://www.virustotal.com/gui/search/" + ipAddrs[1] + "<br><br>\
         <b>======================<br>ADDITIONAL INFORMATION:<br>======================</b><br> \
         <b>Source IP: </b>" + ipAddrs[0] + ", " + ipAddrs[1] +
         "<br><br><b>Destination Username: </b>" + srcUser +
        "<br><br>If you have any questions or concerns, please contact the Security Operations Center (SOC).";
  copyToClip(ticketOut.innerHTML);

  warning.innerHTML = "PLEASE LOOK OVER THE TICKET AND MAKE SURE EVERYTHING MAKES SENSE";
})

UFNPCSummaryButton.addEventListener("click", function(){
    run();

    warning.innerHTML = "PLEASE ONLY TAKE THESE AS A SUGGESTION USE COMMON SENSE";

    ticketOut.innerHTML = summaryText.innerHTML + "<br><br><br><b>INVESTIGATION FINDINGS:</b><br>Our team alerted to the user \
    " + findSrcUser(data) + " authenticating from the country " + findCountry(data) + " which is known to be a non-permissible country\
    in your environment. This user authenticated from the IP address" + findSrcIP(data) + " which was found to be associated with the provider "
    + findVPN(data) + ". It is possible this user is traveling to " + findCountry(data) + ", however, this may be indicative of a threat actor\
    accessing the account. We have seen no other signs of compromise to this user's account. We are reaching out to confirm this activity is expected.\
    Thank you.\
        <br><br><b>RECOMMENDATION(S)/ACTION TAKEN:</b><br>\
        1. Our team recommends verifying the activity with the affected user.<br>\
        2. Our team recommends blocking the affected IP address.<br>\
        3. Our team recommends revoking the user's MFA and forcibly logging the user out.<br><br>\
         <b>REFERENCES/RESOURCES:</b><br>\
         https://www.virustotal.com/gui/search/" + findSrcIP(data) + "<br><br>\
         <b>======================<br>ADDITIONAL INFORMATION:<br>======================</b><br>" + zen_ticket_output_text.innerHTML +
         "If you have any questions or concerns, please contact the Security Operations Center (SOC).";
  copyToClip(ticketOut.innerHTML);

})

MalSummaryButton.addEventListener("click", function(){
    run();

    warning.innerHTML = "PLEASE LOOK OVER THE TICKET AND MAKE SURE EVERYTHING MAKES SENSE";

    ticketOut.innerHTML = summaryText.innerHTML + "<br><br><br><b>INVESTIGATION FINDINGS:</b><br>Our team alerted to the suspicious file \
    " + findFileName(data) + " on the host " + findSrcHost(data) + " which was found to be related to malware during our open source investigation.\
    This file is a known PUP and is related to adware such as browser hijackers or crypto miners. Please review the remediation steps. Thank you!\
        <br><br><b>RECOMMENDATION(S)/ACTION TAKEN:</b><br>\
        1. Our team recommends removing the unwanted program<br>\
        2. Our team recommends scanning the affected host for signs of persistence.<br>\
        3. Our team recommends adding the file hash to the block list.<br><br>\
         <b>REFERENCES/RESOURCES:</b><br>\
         https://www.virustotal.com/gui/search/" + findFileHash(data) + "<br><br>\
         <b>======================<br>ADDITIONAL INFORMATION:<br>======================</b><br>" + zen_ticket_output_text.innerHTML +
         "If you have any questions or concerns, please contact the Security Operations Center (SOC).";
  copyToClip(ticketOut.innerHTML);

})

VPNSummaryButton.addEventListener("click", function(){
    run();

    if(data.hasOwnProperty("source_json") && data["source_json"].hasOwnProperty("category") && data["source_json"]["category"] == "NonInteractiveUserSignInLogs"){
        warning.innerHTML = "PLEASE LOOK OVER THE TICKET AND MAKE SURE EVERYTHING MAKES SENSE";

        ticketOut.innerHTML = summaryText.innerHTML + "<br><br><br><b>INVESTIGATION FINDINGS:</b><br>Our team alerted to the user " + findSrcUser(data) + " authenticating \
    from the IP address " + findSrcIP(data) + " which is related to the VPN\
     " + findVPN(data) + ". While not inherently malicious, a VPN can be misused to avoid accountability\
      by allowing threat actors to connect to a network anonymously or from a different location, and IP,\
       making it difficult to trace their activities. Additionally, a weak encryption algorithm could \
       cause a data breach by making it easier for attackers to intercept and decode sensitive information.\
       This appears to be a non-interactive login, meaning the user's device may be refreshing a session token\
       and the user may not be aware they're authenticating. Please review remediation steps below. Thank you!\
        <br><br><b>RECOMMENDATION(S)/ACTION TAKEN:</b><br>\
        1. Our team recommends revoking the user's session, forcibly logging the user out, and resetting their password and MFA.<br>\
        2. Our team recommends blocking the suspicious IP address.<br>\
        3. Our team recommends reminding the user of the AUP regarding VPNs<br>\
        4. Our team conducted an open source investigation on this IP address and user.<br><br>\
         <b>REFERENCES/RESOURCES:</b><br>\
         https://www.virustotal.com/gui/ip-address/" + findSrcIP(data) + "<br>\
         https://attack.mitre.org/techniques/T1133/<br><br>\
         <b>======================<br>ADDITIONAL INFORMATION:<br>======================</b><br>" + zen_ticket_output_text.innerHTML +
         "If you have any questions or concerns, please contact the Security Operations Center (SOC).";


    } else{
        warning.innerHTML = "PLEASE LOOK OVER THE TICKET AND MAKE SURE EVERYTHING MAKES SENSE";


        ticketOut.innerHTML = summaryText.innerHTML + "<br><br><br><b>INVESTIGATION FINDINGS:</b><br>Our team alerted to the user " + findSrcUser(data) + " authenticating \
    from the IP address " + findSrcIP(data) + " which is related to the VPN\
     " + findVPN(data) + ". While not inherently malicious, a VPN can be misused to avoid accountability\
      by allowing threat actors to connect to a network anonymously or from a different location, and IP,\
       making it difficult to trace their activities. Additionally, a weak encryption algorithm could \
       cause a data breach by making it easier for attackers to intercept and decode sensitive information.\
        Please review remediation steps below. Thank you!\
        <br><br><b>RECOMMENDATION(S)/ACTION TAKEN:</b><br>\
        1. Our team recommends revoking the user's session, forcibly logging the user out, and resetting their password and MFA.<br>\
        2. Our team recommends blocking the suspicious IP address.<br>\
        3. Our team recommends reminding the user of the AUP regarding VPNs<br>\
        4. Our team conducted an open source investigation on this IP address and user.<br><br>\
         <b>REFERENCES/RESOURCES:</b><br>\
         https://www.virustotal.com/gui/ip-address/" + findSrcIP(data) + "<br>\
         https://attack.mitre.org/techniques/T1133/<br><br>\
         <b>======================<br>ADDITIONAL INFORMATION:<br>======================</b><br>" + zen_ticket_output_text.innerHTML +
         "If you have any questions or concerns, please contact the Security Operations Center (SOC).";
    }

  copyToClip(ticketOut.innerHTML);
})

//Copy helper method for copying rich text to clipboard, taken from here:
//https://stackoverflow.com/questions/23934656/how-can-i-copy-rich-text-contents-to-the-clipboard-with-javascript
function copyToClip(str) {
  function listener(e) {
    e.clipboardData.setData("text/html", str);
    e.clipboardData.setData("text/plain", str);
    e.preventDefault();
  }
  document.addEventListener("copy", listener);
  document.execCommand("copy");
  document.removeEventListener("copy", listener);
};


function run(){
    
    let inputText = document.getElementById("input").value;

    if(inputText[0]=="{"){
        //generate JS object from elastic JSON
        data = JSON.parse(inputText);
    } else {
        data = parseCB(inputText);
    }

    parseAndPrintJSON(data);
    
}

function parseCB(inputText){
    let infoArr = inputText.split("\n");  
    let tmp = '{"fields":{ "user.name":["' + infoArr[0] +'"], "host.name":["'+infoArr[2]+'"], "user_agent.os.full":["'+infoArr[1]+'"], "src.ip":["'+infoArr[3]+'"], "file.name":["'+infoArr[4]+'"],"file.hash.sha256":["'+infoArr[5]+'"]}}'
    let JSONdata = JSON.parse(tmp);
    return JSONdata;
}

function parseAndPrintJSON(data){

    let breakLine = "&nbsp;\n";

    let summaryCtrl = true;

    let sourceInfo = false; //used to determine if any info about the source was found.
    let srcHost = findSrcHost(data);
    let srcIP = findSrcIP(data);
    let srcUser = findSrcUser(data);
    let srcDomain = findSrcDomain(data);
    let srcOS = findSrcOS(data);

    let destInfo = false; //used to determine if any info about the destination was found.
    let destHost = findDestHost(data);
    let destIP = findDestIP(data);
    let destUser = findDestUser(data);
    let destDomain = findDestDomain(data);
    let destOS = findDestOS(data);

    let fileInfo = false; //used to determine if any info about the file was found.
    let fileName = findFileName(data);
    let filePath = findFilePath(data);
    let fileHash = findFileHash(data);

    let processInfo = false; //used to determine if any info about the process was found.
    let processName = findProcessName(data);
    let processPath = findProcessPath(data);

    let cmdLine = findCommandLine(data);

    //strings used to build and set output value
    zenMarkupOut = ""
    zen_ticket_parsed = ""


    // series of checks to determine if target field was found. If so, add the field to both output builder strings and set appropriate flag boolean
    //source info
    if( srcHost != "" ){
        zenMarkupOut += "**Source Hostname:** " + srcHost;
        zen_ticket_parsed += "Source Hostname: ".bold() + srcHost + "<br>";
        sourceInfo = true; //this is setting the flag boolean
    }
    if(srcIP != "" ){
        zenMarkupOut += "**Source IP:** " + srcIP;
        zen_ticket_parsed += "Source IP: ".bold() + srcIP + "<br>";
        sourceInfo = true;
    }
    if(srcUser != "" ){
        zenMarkupOut += "**Source User:** " + srcUser;
        zen_ticket_parsed += "Source User: ".bold() + srcUser + "<br>";
        sourceInfo = true;
    }
    if(srcDomain != "" ){
        zenMarkupOut += "**Source Domain:** " + srcDomain;
        zen_ticket_parsed += "Source Domain: ".bold() + srcDomain + "<br>";
        sourceInfo = true;
    }
    if(srcOS != "" ){
        zenMarkupOut += "**Source OS:** " + srcOS;
        zen_ticket_parsed += "Source OS: ".bold() + srcOS + "<br>";
        sourceInfo = true;
    }
    if(sourceInfo){
        zenMarkupOut+=breakLine;
        zen_ticket_parsed+="<br>";
    }

    //destination info
    if( destHost != "" ){
        zenMarkupOut += "**Destination Hostname:** " + destHost;
        zen_ticket_parsed += "Destination Hostname: ".bold() + destHost + "<br>";
        destInfo = true;
    }
    if(destIP != "" ){
        zenMarkupOut += "**Destination IP:** " + destIP;
        zen_ticket_parsed += "Destination IP: ".bold() + destIP + "<br>";
        destInfo = true;
    }
    if(destUser != "" ){
        zenMarkupOut += "**Destination User:** " + destUser;
        zen_ticket_parsed += "Destination User: ".bold() + destUser + "<br>";
        destInfo = true;
    }
    if(destDomain != "" ){
        zenMarkupOut += "**Destination Domain:** " + destDomain;
        zen_ticket_parsed += "Destination Domain: ".bold() + destDomain + "<br>";
        destInfo = true;
    }
    if(destOS != "" ){
        zenMarkupOut += "**Destination OS:** " + destOS;
        zen_ticket_parsed += "Destination OS: ".bold() + destOS + "<br>";
        destInfo = true;
    }
    if(destInfo){
        zenMarkupOut+=breakLine;
        zen_ticket_parsed+="<br>";
    }

    //file info
    if(fileName != ""){
        zenMarkupOut += "**File Name:** " + fileName;
        zen_ticket_parsed += "File Name: ".bold() + fileName + "<br>";
        fileInfo = true;
    }
    if(filePath != ""){
        zenMarkupOut += "**File Path:** " + filePath;
        zen_ticket_parsed += "File Path: ".bold() + filePath + "<br>";
        fileInfo = true;
    }
    if(fileHash != ""){
        zenMarkupOut += "**File Hash:** " + fileHash;
        zen_ticket_parsed += "File Hash: ".bold() + fileHash + "<br>";
        fileInfo = true;
    }
    if(fileInfo){
        zenMarkupOut+=breakLine;
        zen_ticket_parsed+="<br>";
    }

    //process info
    if(processName != ""){
        zenMarkupOut += "**Process Name:** " + processName;
        zen_ticket_parsed += "Process Name: ".bold() + processName + "<br>";
        processInfo = true;
    }
    if(processPath != ""){
        zenMarkupOut += "**Process Path:** " + processPath;
        zen_ticket_parsed += "Process Path: ".bold() + processPath + "<br>";
        processInfo = true;
    }
    if(processInfo){
        zenMarkupOut+=breakLine;
        zen_ticket_parsed+="<br>";
    }

    //command line info. This one does not print to paragraph due to lack of support in rich text
    if (cmdLine != ""){
        zenMarkupOut += "**Command Line:**\n```\n" + cmdLine + "\n```";
    }

    //setting Summary output
    let summaryStr = "alerted to the "
    if(srcUser != ""){
        if(srcHost != ""){
            if(fileName != ""){
                summaryStr += "file " + fileName + " from the user " + srcUser + " on the host "+srcHost;
            }else if(processName!=""){
                summaryStr += "process " + processName + " from the user " + srcUser + " on the host "+srcHost;
            } else{
                summaryStr += "user " + srcUser + " from the IP "+srcIP;
            }
        } else if(srcIP != ""){
            if(fileName != ""){
                summaryStr += "file " + fileName + " from the user " + srcUser + " from the IP "+srcIP;
            } else if(processName!=""){
                summaryStr += "process " + processName + " from the user " + srcUser + " from the IP "+srcIP;
            } else{
                summaryStr += "user " + srcUser + " from the IP "+srcIP;
            }
        }
    }
    summaryText.innerHTML = summaryStr + " as a potential threat in your environment.";

    zen_ticket_output_text.innerHTML = zen_ticket_parsed;
    zenOut.value = zenMarkupOut;

}

//Following methods check if the fields can be parsed from the JSON object. If so return, if not, log to console and return blank string.

//Source stats
function findSrcHost(data){


    if(data.hasOwnProperty("hostname")){
        return data["hostname"] + "\n";
    } else if(data.hasOwnProperty("source_asset")){
        return data["source_asset"] + "\n";
    } else if(data.hasOwnProperty("asset")){
        return data["asset"] + "\n";
    }

    try{
        return data["fields"]["host.name"][0] + "\n";
    } catch(error){
        console.log("Error finding host name. No host found.");
        return "";
    }

}

function findSrcIP(data){

    //r7
    if(data.hasOwnProperty("source_ip")){
        return data["source_ip"] + "\n";
    } else if(data.hasOwnProperty("ip_address")){
        return data["ip_address"] + "\n";
    } else if(data.hasOwnProperty("source_address")){
        return data["source_address"] + "\n";
    }else if(data.hasOwnProperty("senderIP")){
        return data["senderIP"] + "\n";
    } else if(data.hasOwnProperty("source_json") && data["source_json"].hasOwnProperty("ClientIP")){ 
        return data["source_json"]["ClientIP"]+"\n";
    } else if(data.hasOwnProperty("source_asset_address")){ 
        return data["source_asset_address"]+"\n";
    }

    //elastic
    try{
        return data["fields"]["source.ip"][0] + "\n";
    } catch(error){
        try{
            return data["fields"]["host.ip"][0] + "\n";
        } catch(error){
            console.log("Error finding source IP name. No source IP found.");
            return "";
        }
    }

}

function findSrcUser(data){

    //TODO: find o365.audit.data and parse for source IP, source user

    if(data.hasOwnProperty("user") && data["user"] != "unknown"){
        return data["user"] + "\n";
    } else if(data.hasOwnProperty("account")){
        return data["account"] + "\n";
    } else if(data.hasOwnProperty("source_account")){
        return data["source_account"] + "\n";
    } else if(data.hasOwnProperty("process") && data["process"].hasOwnProperty("username")){ //short circuit logic
        return data["process"]["username"] + "\n";
    } else if(data.hasOwnProperty("fromAddress")){
        return data["fromAddress"][0] + "\n";
    } else if(data.hasOwnProperty("source_local_account")){
        return data["source_local_account"][0] + "\n";
    }

    try{
        return data["fields"]["user.name"][0] + "\n";
    } catch(error){
        try{
            return data["fields"]["user.email"][0] + "\n";
        } catch(error){
            try{
                return data["fields"]["user.id"][0] + "\n";
            } catch(error){
                try{
                    return data["fields"]["o365.audit.UserId"][0] + "\n";
                } catch(error){
                    try{
                        return data["source.user.name"][0] + "\n";
                        //todo winlog.user.name
                    } catch (error){
                        try{
                            return data["fields"]["winlog.user.name"][0] + "\n";
                        } catch (error) {
                            return "";
                        }
                    }
                }
            }
        }
    }


}

function findSrcDomain(data){

    if(data.hasOwnProperty("process") && data["process"].hasOwnProperty("account_domain")){
        return data["process"]["account_domain"] + "\n";
    } else if(data.hasOwnProperty("dns_domain")){
        return data["dns_domain"] + "\n";
    }

    try{
        return data["fields"]["user.domain"][0] + "\n";
    } catch(error){
        console.log("Error finding source domain name.");
        return "";
    }

}

function findSrcOS(data){

    if(data.hasOwnProperty("os_type")){
        return data["os_type"] + "\n";
    } else if (data.hasOwnProperty("source_json") && data["source_json"].hasOwnProperty("DeviceProperties")){ //short circuit for finding sourcejson + device props
        let tmp = data["source_json"]["DeviceProperties"] //Keepin it D.R.Y.
        for(let i=0; i<=tmp.length; i++){
            if(tmp && tmp[i].Name == "OS"){
                return tmp[i].Value+"\n";
            }
        }
    }

    try{
        return data["fields"]["host.os.Ext.variant"][0] + "\n";
    } catch(error){
        try{
            return data["fields"]["user_agent.os.full"][0] + "\n";
        } catch(error){
            console.log("Error finding source OS");
            return "";
        }
    }

}

//Destination stats
function findDestHost(data){

    //Not usually supported due to limitations of logs and tools

    if(data.hasOwnProperty("target_address")){
        return data["target_address"] + "\n";
    } else if(data.hasOwnProperty("destination_asset_address")){
        return data["destination_asset_address"] + "\n";
    }

    try{
        return + data["fields"]["destination.host.name"][0] + "\n";
    } catch(error){
        console.log("Error finding destination host name. No destination host found.");
        return "";
    }

}

function findDestIP(data){

    if(data.hasOwnProperty("destination_ip")){
        return data["destination_ip"] + "\n";
    } else if(data.hasOwnProperty("destination_address")){
        return data["destination_address"] + "\n";
    }

    try{
        return data["fields"]["destination.ip"][0] + "\n";
    } catch(error){
        console.log("Error finding destination IP name. No destination IP found.");
        return "";
    }

}

function findDestUser(data){

    //rapid7
    if(data.hasOwnProperty("target_user_name")){
        return data["target_user_name"] + "\n";
    }
    else if(data.hasOwnProperty("recipient")){
        return data["recipient"] + "\n";
    }
    else if(data.hasOwnProperty("ccAddresses")){
        let ret_str = "";
        for(let i=0; i<data["ccAddresses"].length; i++){
            ret_str+=data["ccAddresses"][i]+"\n"
        }
        return "\n" + ret_str;
    }
    else if(data.hasOwnProperty("source_json") && data["source_json"].hasOwnProperty("Parameters")){
        let tmp = data["source_json"]["Parameters"];
        for(let i=0; i<tmp.length; i++){
            if(tmp[i].Name == "ForwardTo" || tmp[i].Name=="ForwardingSmtpAddress"){
                return tmp[i].Value+"\n";
            }
        }
    }
    else if(data.hasOwnProperty("destination_local_account")){
        return data["destination_local_account"] + "\n";
    }
    else if(data.hasOwnProperty("destination_user")){
        return data["destination_user"] + "\n";
    }
    else if (data.hasOwnProperty("destination_account")){
        return data["destination_account"] + "\n";
    }

    //elastic
    try{
        return data["fields"]["user.target.name"][0] + "\n";
    } catch(error){
        try{
            return data["fields"]["o365.audit.ObjectId"][0] + "\n";
        } catch (error){
            try{
                return data["fields"]["winlog.event_data.SubjectUseName"][0] + "\n";
            } catch (error){
                console.log("Error finding destination user name. No destination user found.");
                return "";}
        }
    }

}

function findDestDomain(data){

    if(data.hasOwnProperty("source_json") && data["source_json"].hasOwnProperty("Entities")){
        let tmp = data["source_json"]["Entities"];
        for(let i=0; i<tmp.length; i++){
            if(tmp[i].hasOwnProperty("DomainName")){
                return tmp[i]["DomainName"]+"\n";
            }
        }
    }

    try{
        return data["fields"]["destination.domain"][0] + "\n";
    } catch(error){
        console.log("Error finding destination domain name. No destination domain found.");
        return "";
    }

}

function findDestOS(data){

    //Not supported due to limitations of logs and tools

    try{
        return data["fields"]["destination.os"][0] + "\n";
    } catch(error){
        console.log("Error finding destination OS name. No destination OS found.");
        return "";
    }

}

//File
function findFileName(data){

    if(data.hasOwnProperty("process") && data["process"].hasOwnProperty("exe_file") && data["process"]["exe_file"].hasOwnProperty("orig_filename")){
        return data["process"]["exe_file"]["orig_filename"] + "\n";
    } else if(data.hasOwnProperty("file_name")){
        return data["file_name"] + "\n";
    }

    try{
        return data["fields"]["file.name"][0] + "\n";
    } catch(error){
        console.log("Error finding file name. No file name found.");
        return "";
    }

}

function findFilePath(data){

    if(data.hasOwnProperty("file_path")){
        return data["file_path"] + "\n";
    }

    try{
        return data["fields"]["file.path"][0] + "\n";
    } catch(error){
        console.log("Error finding file path. No file path found.");
        return "";
    }

}

function findFileHash(data){

    if(data.hasOwnProperty("process") && data["process"].hasOwnProperty("exe_file") && data["process"]["exe_file"].hasOwnProperty("hashes")){

        if(data["process"]["exe_file"]["hashes"].hasOwnProperty("sha256")){
            return data["process"]["exe_file"]["hashes"]["sha256"] + "\n";
        } else if(data["process"]["exe_file"]["hashes"].hasOwnProperty("sha1")){
            return data["process"]["exe_file"]["hashes"]["sha1"] + "\n";
        } else if(data["process"]["exe_file"]["hashes"].hasOwnProperty("md5")){
            return data["process"]["exe_file"]["hashes"]["md5"] + "\n";
        }
        
    }

    try{ //ask if better field to use
        return data["fields"]["file.hash.sha256"][0] + "\n";
    } catch(error){
        console.log("Error finding file hash. No file hash found.");
        return "";
    }

}

function findProcessName(data){

    if(data.hasOwnProperty("process") && data["process"].hasOwnProperty("name")){
        return data["process"]["name"] + "\n";
    }

    try{
        return data["fields"]["process.name"][0] + "\n";
    } catch(error){
        console.log("Error finding process name. No process name found.");
        return "";
    }

}

function findProcessPath(data){

    if(data.hasOwnProperty("process") && data["process"].hasOwnProperty("exe_path")){
        return data["process"]["exe_path"] + "\n";
    }

    try{
        return data["fields"]["process.executable"][0] + "\n";
    } catch(error){
        console.log("Error finding process path. No process path found.");
        return "";
    }

}

function findCommandLine(data){

    if(data.hasOwnProperty("process") && data["process"].hasOwnProperty("cmd_line")){
        return data["process"]["cmd_line"];
    }

    try{
        return data["fields"]["process.command_line"][0];
    } catch(error){
        console.log("Error finding command_line. No command_line found.");
        return "";
    }

}

function findVPN(data){
    if(data.hasOwnProperty("geoip_organization")){
        return data["geoip_organization"];
    }
}

function findCountry(data){
    if(data.hasOwnProperty("geoip_country_name")){
        return data["geoip_country_name"];
    }
}

function findDC(data){
    if (
        data.hasOwnProperty("source_json") && data["source_json"].hasOwnProperty("isDomainController")
        )
    {
        return data["source_json"]["isDomainController"];
    }
}

function findPasswordFile(data){

    //requireed to split on newline due to handling zendesk parsing in cmd_line
    cmd_line = findCommandLine(data);
    passArray = cmd_line.split('"');

    for(let i=0; i<passArray.length; i++){
        comparePass = passArray[i].toLowerCase();
        if(comparePass.includes("password") || comparePass.includes("credentials") || comparePass.includes("cred")){
            return passArray[i];
        }
    }
    return cmd_line;
}