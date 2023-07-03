/ Load cCryptoGS library
var cCryptoGS = cCryptoGS || undefined;

function getSignatureKey(key, date, region, service) {
  var kDate = computeHmacSHA256('AWS4' + key, date);
  var kRegion = computeHmacSHA256(kDate, region);
  var kService = computeHmacSHA256(kRegion, service);
  var kSigning = computeHmacSHA256(kService, 'aws4_request');
  return kSigning;
}

function computeHmacSHA256(key, data) {
  var signature = Utilities.computeHmacSha256Signature(data, key);
  var signatureBytes = [];
  for (var i = 0; i < signature.length; i++) {
    signatureBytes.push(String.fromCharCode(signature[i]));
  }
  return Utilities.base64Encode(signatureBytes.join(''));
}

function createAWSSignatureV4(accessKey, secretKey, region, service, timestamp, payload) {
  var algorithm = 'AWS4-HMAC-SHA256';
  var method = 'POST';
  var canonicalUri = '/';
  var canonicalQueryString = '';
  var canonicalHeaders = 'content-type:application/x-www-form-urlencoded\nhost:' + service + '.' + region + '.amazonaws.com\nx-amz-date:' + timestamp + '\n';
  var signedHeaders = 'content-type;host;x-amz-date';
  var canonicalRequest = method + '\n' + canonicalUri + '\n' + canonicalQueryString + '\n' + canonicalHeaders + '\n' + signedHeaders + '\n' + payload;

  var date = timestamp.slice(0, 8);
  var credentialScope = date + '/' + region + '/' + service + '/aws4_request';
  var stringToSign = algorithm + '\n' + timestamp + '\n' + credentialScope + '\n' + computeHmacSHA256(secretKey, canonicalRequest);

  var signatureKey = getSignatureKey(secretKey, date, region, service);
  var signature = computeHmacSHA256(signatureKey, stringToSign);

  var authorizationHeader = algorithm + ' Credential=' + accessKey + '/' + credentialScope + ', SignedHeaders=' + signedHeaders + ', Signature=' + signature;

  return authorizationHeader;
}

function generateTimestamp() {
  var now = new Date();
  var year = now.getUTCFullYear();
  var month = ('0' + (now.getUTCMonth() + 1)).slice(-2);
  var day = ('0' + now.getUTCDate()).slice(-2);
  var hours = ('0' + now.getUTCHours()).slice(-2);
  var minutes = ('0' + now.getUTCMinutes()).slice(-2);
  var seconds = ('0' + now.getUTCSeconds()).slice(-2);
  
  var timestamp = year + month + day + 'T' + hours + minutes + seconds + 'Z';
  
  return timestamp;
}

function testSignatureGeneration() {
  var accessKey = 'YOUR-ACCESS-KEY';
  var secretKey = 'YOUR-SECRET-KEY';
  var region = 'YOUR-REGION';
  var service = 'ce'; //in this case, "ce" is for cost explorer. you might want to check for other services.
  var payload = '';

  var timestamp = generateTimestamp();
  var signature = createAWSSignatureV4(accessKey, secretKey, region, service, timestamp, payload);
  console.log(signature);
}
