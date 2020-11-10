function computeResponse(obj){
  var challenge = document.getElementById('challenge').value;

  //Credit to https://stackoverflow.com/questions/36018233/how-to-load-a-pkcs12-digital-certificate-with-javascript-webcrypto-api
  //alert(challenge)
  
  // Read from file input
  var file = document.getElementById('file').files[0];
  var reader = new FileReader();
  
  reader.onload = function(e) {               
    var contents = e.target.result;
    var pkcs12Der = arrayBufferToString(contents)
    
    // decode DER format to ASN1 and read content with forge
    var pkcs12Asn1 = forge.asn1.fromDer(pkcs12Der);
    var pkcs12 = forge.pkcs12.pkcs12FromAsn1(pkcs12Asn1,);

    // extract private key
    var privateKey = get_private_key(pkcs12);

    // Convert to PKCS8 format
    var privateKeyPkcs8 = _privateKeyToPkcs8(privateKey);

    // Import into WebCrypto
    _importCryptoKeyPkcs8(privateKeyPkcs8, false).    
        then(function(cryptoKey) {
          sign_content(cryptoKey, challenge.toString());
        });
  }
  reader.readAsArrayBuffer(file);
}

function sign_content(privateKey, content) {
  //var digestToSign = forge.util.decode64(content);
  var digestToSignBuf = stringToArrayBuffer(content);

  crypto.subtle.sign(
            {name: "RSASSA-PKCS1-v1_5"},
            privateKey,
            digestToSignBuf)
  .then(function(signature){
    var signatureB64 = forge.util.encode64(arrayBufferToString(signature));

    // Put signature in the hidden form
    document.getElementById('challenge').value = signatureB64;

    // Once asynchronous calls are done, submit the form!
    form.submit()
  });
}

function _importCryptoKeyPkcs8(privateKey, extractable) {
  return crypto.subtle.importKey(
          'pkcs8', 
          privateKey, 
          { name: "RSASSA-PKCS1-v1_5", hash:{name:"SHA-256"}},
          extractable, 
          ["sign"]);        
}

function _privateKeyToPkcs8(privateKey) {
  var rsaPrivateKey = forge.pki.privateKeyToAsn1(privateKey);
  var privateKeyInfo = forge.pki.wrapRsaPrivateKey(rsaPrivateKey);
  var privateKeyInfoDer = forge.asn1.toDer(privateKeyInfo).getBytes();
  var privateKeyInfoDerBuff = stringToArrayBuffer(privateKeyInfoDer);
  return privateKeyInfoDerBuff;
}

function stringToArrayBuffer(data){
  var arrBuff = new ArrayBuffer(data.length);
  var writer = new Uint8Array(arrBuff);
  for (var i = 0, len = data.length; i < len; i++) {
      writer[i] = data.charCodeAt(i);
  }
  return arrBuff;
}

function get_private_key(pkcs12){
  for(var sci = 0; sci < pkcs12.safeContents.length; ++sci) {
    var safeContents = pkcs12.safeContents[sci];

    for(var sbi = 0; sbi < safeContents.safeBags.length; ++sbi) {
        var safeBag = safeContents.safeBags[sbi];

        // this bag has a private key
        if(safeBag.type === forge.pki.oids.keyBag) {
            //Found plain private key
            privateKey = safeBag.key;
        } else if(safeBag.type === forge.pki.oids.pkcs8ShroudedKeyBag) {
            // found encrypted private key
            privateKey = safeBag.key;
        } else if(safeBag.type === forge.pki.oids.certBag) {
            // this bag has a certificate...        
        }   
    }
  }
  return privateKey
}

function arrayBufferToString( buffer ) {
  var binary = '';
  var bytes = new Uint8Array( buffer );
  var len = bytes.byteLength;
  for (var i = 0; i < len; i++) {
      binary += String.fromCharCode( bytes[ i ] );
  }
  return binary;
}


function loginSHA(obj){
  var pwdObj = document.getElementById('password');

  if (pwdObj.value != ""){
    pwdObj.value = hash(pwdObj.value);
  }  
}

function updateInfoSHA(obj){
  var pwdObj = document.getElementById('password');

  if (pwdObj.value != ""){
    pwdObj.value = hash(pwdObj.value);
  }  
}

function revokeSHA(obj){
  var pwdObj = document.getElementById('password3');

  if (pwdObj.value != ""){
    pwdObj.value = hash(pwdObj.value);
  }  
}

function issueCertSHA(obj){
  // Compute SHA-1 of password before submitting the form
  var pwdObj = document.getElementById('password2');
  if (pwdObj.value != ""){
    pwdObj.value = hash(pwdObj.value);
  }

  // Alert to check that user knows the old cert will be revoked
  return confirm("When issuing a new certificate the previous one will be automatically revoked. Are you sure you want to proceed?")
}

function hash(text) {
  var hashObj = new jsSHA("SHA-1", "TEXT", {numRounds: 1});
  hashObj.update(text);
  var hash = hashObj.getHash("HEX");
  return hash
}

function requirePassword(obj){
  var txt;
  var password = prompt("Please enter your password:");
  if (password == null || password == "") {
    txt = "User cancelled the prompt.";
  } else {
    alert("Password hash is "+hash(password))
  }
}