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