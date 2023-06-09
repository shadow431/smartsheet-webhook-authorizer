require 'dotenv'
Dotenv.load
require 'openssl'
require 'logger'
require 'json'
require 'aws-sdk-eventbridge'


$logger = Logger.new(STDOUT)
$logger.level = Logger::DEBUG

def handler(event:, context:)
  $logger.debug event
  challengeHeader = 'smartsheet-hook-challenge'
  responseHeader = 'Smartsheet-Hook-Response'
  hmacHeader = 'smartsheet-hmac-sha256'
  sharedSecret = ENV['sharedSecret']
  request = event
  data = request['body']
#  $logger.debug data
  case request['requestContext']['http']['method']
  when 'POST'
    pData = JSON.parse(data)
    $logger.info "POST"
    $logger.debug request['headers']
    if request['headers'].has_key?(challengeHeader)
      $logger.info "Challege Request"
      {'statusCode' => 200, 'headers' => {"Content-Type" => "text/plain", "#{responseHeader}" => "#{request['headers'][challengeHeader]}"}, 'body' => ""}
    elsif request['headers'].has_key?(hmacHeader)
      $logger.info "Has HMAC"
      if request['headers'][hmacHeader] != calcHmac(sharedSecret,data)
        $logger.info "Access Denied - Bad HMAC"
        {'statusCode' => 403, 'headers' => {"Content-Type" => "application/json"}, 'body' => {"Response" => "Not Authorized!!! GO AWAY!!!!"}.to_json }
      else
        $logger.info "Setting event"
        placeEvent(data)
        {'statusCode' => 200, 'headers' => {"Content-Type" => "application/json"}, 'body' => {"Response" => "Event created"}.to_json }
      end
    else
      $logger.info "Access Denied - No Header"
      {'statusCode' => 403, 'headers' => {"Content-Type" => "application/json"}, 'body' => {"Response": "Not Authorized!!! GO AWAY!!!!"}.to_json }
    end
  when 'GET'
    $logger.info "Access Denied - GET"
    {'statusCode' => 403, 'headers' => {"Content-Type" => "application/json"},  'body' => {"Response": "Not Authorized!!! GO AWAY!!!!"}.to_json }
  else
    $logger.info "IDK IDC"
    {'statusCode' => 404, 'headers' => {}, 'body' => {"Response": "Did you get lost?"}.to_json }
  end
end

def calcHmac(key,data)
  hmac = OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new('sha256'),key,data)
  $logger.debug hmac
  $logger.debug key
  return hmac
end

def placeEvent(data)
  #publish data to an event bus
  $logger.debug "Placing event"

  eventbridge = Aws::EventBridge::Client.new(region: ENV['region'])
  $logger.debug eventbridge.put_events({entries: [{source: 'smartsheet', detail_type: 'smartsheet', detail: data, event_bus_name: ENV['eventBusName']}]})

  return "I didn't do anything"
end
