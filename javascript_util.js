const aws4  = require('./aws4');
const fs = require('fs');
const { X509Certificate } = require('crypto');
const args = process.argv.slice(2);

if(args[0] == "sign") {
    generateAuthHeaderWithSignature();
}

if(args[0] == "parse_secret") {
    parseSecretString();
}

if(args[0] == "list_certs") {
    listAllCerts();
}

if(args[0] == "restore_old_cert") {
    listOldCerts();
}

if(args[0] == 'days_to_expire') {
    calculateDaysToExpire();
}

function generateAuthHeaderWithSignature() {
    const creds = JSON.parse(args[1]);
    var opts = JSON.parse(args[2]);
    aws4.sign(opts, creds);
    fs.writeFileSync("tempFile", opts.headers['Authorization'] + "\n");
    fs.writeFileSync("tempFile", opts.headers['X-Amz-Date'], {flag: "a"});
}

function parseSecretString() {
    var secret = fs.readFileSync("tempFile").toString();
    secret = JSON.parse(secret).SecretString;
    secret = JSON.parse(secret);
    secret = secret[Object.keys(secret)[0]];
    var startIndex = secret.indexOf("- ");
    var endIndex = secret.indexOf(" -");
    var start = secret.substring(0,startIndex+1);
    var end = secret.substring(endIndex+1, secret.length);
    var secretBody = secret.substring(startIndex+2, endIndex).replace(/ /g, "\n");
    secret = start + "\n" + secretBody + "\n" + end ;
    fs.writeFileSync("tempFile", secret);
}

function listAllCerts() {
    var secrets = fs.readFileSync("tempFile").toString();
    secrets = JSON.parse(secrets);
    if(secrets.NextToken != null) {
        fs.writeFileSync("nextToken", secrets.NextToken);
    }
    secrets = secrets.SecretList;
    var certUpdated;
    try {
        certUpdated = fs.readFileSync("isCertUpdated").toString();
        if(certUpdated == "true") {
            certUpdated = true;
        } else {
            certUpdated = false;
        }
    } catch(err) {
        certUpdated = false;
    }
    
    // getting current time in Asia/Kolkata timezone
    var currentTime = new Date((new Date()).toLocaleString("en-US", {timeZone: "Asia/Kolkata"}));
    var hrs = parseInt(args[1]);
    time_window = hrs * 60 * 60 * 1000;

    var dlbList = new Set();

    for(let i=0; i < secrets.length; i++) {

        var secretName = secrets[i].Name

        // getting and converting last changed date of secret in Asia/Kolkata timezone 
        var lastChanged = secrets[i].LastChangedDate;
        lastChanged = new Date((new Date(0)).setUTCSeconds(lastChanged));
        lastChanged = new Date(lastChanged.toLocaleString("en-US", {timeZone: "Asia/Kolkata"}));

        // check if certificate is updated within 24 hours
        if(currentTime.getTime() - lastChanged.getTime() <= time_window) {
            certUpdated = true;
            var dlbName = secretName.substr(0, secretName.indexOf('/'));
            if(dlbName != null && dlbName != "") {
                dlbList.add(dlbName);
            }
        }

        fs.writeFileSync("certList", secretName + "\r\n", {flag: "a"});
    }

    // storing dlb names in a file to be accessed by bash script
    [...dlbList].forEach(dlbName => fs.writeFileSync("dlbList", dlbName + "\r\n", {flag: "a"}))
    

    if(certUpdated) {
        fs.writeFileSync("isCertUpdated", "true");
    } else {
        fs.writeFileSync("isCertUpdated", "false");
    }

}

function listOldCerts() {
    var secrets = fs.readFileSync("tempFile").toString();
    secrets = JSON.parse(secrets);
    if(secrets.NextToken != null) {
        fs.writeFileSync("nextToken", secrets.NextToken);
    }
    secrets = secrets.SecretList;
    
    // getting current time in Asia/Kolkata timezone
    var currentTime = new Date((new Date()).toLocaleString("en-US", {timeZone: "Asia/Kolkata"}));
    var hrs = parseInt(args[1]);
    var time_window = hrs * 60 * 60 * 1000;

    var dlbList = new Set();

    for(let i=0; i < secrets.length; i++) {

        var secretName = secrets[i].Name

        // getting and converting last changed date of secret in Asia/Kolkata timezone 
        var lastChanged = secrets[i].LastChangedDate;
        lastChanged = new Date((new Date(0)).setUTCSeconds(lastChanged));
        lastChanged = new Date(lastChanged.toLocaleString("en-US", {timeZone: "Asia/Kolkata"}));

        // check if certificate is updated within 24 hours
        if(currentTime.getTime() - lastChanged.getTime() > time_window) {
            var dlbName = secretName.substr(0, secretName.indexOf('/'));
            if(dlbName != null && dlbName != "") {
                dlbList.add(dlbName);
            }
            fs.writeFileSync("certList", secretName + "\r\n", {flag: "a"});
        }

    }

    // storing dlb names in a file to be accessed by bash script
    [...dlbList].forEach(dlbName => fs.writeFileSync("dlbList", dlbName + "\r\n", {flag: "a"}))

}

function calculateDaysToExpire() {
    var certificate = fs.readFileSync("tempFile").toString();
    certificate = certificate.replace(/ +(?!(CERTIFICATE))/g, '\n');
    try{
        const certDetails = new X509Certificate(certificate);
        var expDate = new Date(certDetails.validTo);
        var today = new Date();
        var daysForExpiry = Math.ceil((expDate.getTime() - today.getTime())/(1000 * 60 * 60 * 24));
        fs.writeFileSync("daysToExpire", daysForExpiry.toString());
        
    }catch(e) {
        fs.writeFileSync("daysToExpire", "Invalid");
    }
}
