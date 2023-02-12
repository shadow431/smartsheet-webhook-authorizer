require 'dotenv'
Dotenv.load
require 'openssl'
require 'logger'
require 'json'

$logger = Logger.new(STDOUT)
$logger.level = Logger::DEBUG

def handler(event:, context:)
  $logger.debug event
  challengeHeader = 'HTTP_Smartsheet-Hook-Challenge'.upcase.gsub('-','_')
  responseHeader = 'Smartsheet-Hook-Response'
  hmacHeader = 'HTTP_Smartsheet-Hmac-SHA256'.upcase.gsub('-','_')
  sharedSecret = ENV['sharedSecret']
  request = event
  data = request #.body.read
#  $logger.debug data
  case request.http.method
  when 'POST'
    pData = JSON.parse(data)
    $logger.info "POST"
    if request.has_header?(challengeHeader)
      $logger.info "Challege Request"
      [200, {"Content-Type" => "text/plain", "#{responseHeader}" => "#{request.get_header(challengeHeader)}"}, []]
    elsif request.has_header?(hmacHeader)
      $logger.info "Has HMAC"
      if request.get_header(hmacHeader) != calcHmac(sharedSecret,data)
        $logger.info "Access Denied - Bad HMAC"
        [403, {"Content-Type" => "application/json"}, ["{\"Response\": \"Not Authorized!!! GO AWAY!!!!\"}\n"]]
      else
        $logger.info "Setting event"
        [200, {"Content-Type" => "application/json"}, ["{\"Event created\": \"#{event}\"}\n"]]
      end
    else
      $logger.info "Access Denied - No Header"
      [403, {"Content-Type" => "application/json"}, ["{\"Response\": \"Not Authorized!!! GO AWAY!!!!\"}\n"]]
    end
  when 'GET'
    $logger.info "Access Denied - GET"
    [403, {"Content-Type" => "application/json"}, ["{\"Response\": \"Not Authorized!!! GO AWAY!!!!\"}\n"]]
  else
    $logger.info "IDK IDC"
    [404, {}, ["Did you get lost?\n"]]
  end
end

def calcHmac(key,data)
  hmac = OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new('sha256'),key,data)
  $logger.debug hmac
  $logger.debug key
  return hmac
end

def placeEvent()
  return "I didn't do anything"
end
=begin
{
  "version": "2.0",
  "type": "REQUEST",
  "routeArn": "arn:aws:execute-api:us-east-1:123456789012:abcdef123/test/GET/request",
  "identitySource": ["user1", "123"],
  "routeKey": "$default",
  "rawPath": "/my/path",
  "rawQueryString": "parameter1=value1&parameter1=value2&parameter2=value",
  "cookies": ["cookie1", "cookie2"],
  "headers": {
    "HTTP_Smartsheet-Hook-Challenge": "value1",
    "HTTP_Smartsheet-Hmac-SHA256": "value1",
  },
  "queryStringParameters": {
    "parameter1": "value1,value2",
    "parameter2": "value"
  },
  "requestContext": {
    "accountId": "123456789012",
    "apiId": "api-id",
    "authentication": {
      "clientCert": {
        "clientCertPem": "CERT_CONTENT",
        "subjectDN": "www.example.com",
        "issuerDN": "Example issuer",
        "serialNumber": "a1:a1:a1:a1:a1:a1:a1:a1:a1:a1:a1:a1:a1:a1:a1:a1",
        "validity": {
          "notBefore": "May 28 12:30:02 2019 GMT",
          "notAfter": "Aug  5 09:36:04 2021 GMT"
        }
      }
    },
    "domainName": "id.execute-api.us-east-1.amazonaws.com",
    "domainPrefix": "id",
    "http": {
      "method": "POST",
      "path": "/my/path",
      "protocol": "HTTP/1.1",
      "sourceIp": "IP",
      "userAgent": "agent"
    },
    "requestId": "id",
    "routeKey": "$default",
    "stage": "$default",
    "time": "12/Mar/2020:19:03:58 +0000",
    "timeEpoch": 1583348638390
  },
  "pathParameters": { "parameter1": "value1" },
  "stageVariables": { "stageVariable1": "value1", "stageVariable2": "value2" }
}
=end
