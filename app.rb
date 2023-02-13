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
