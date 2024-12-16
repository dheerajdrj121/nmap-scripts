# Custom NSE Scripts
# =======================================

## Script 1: Check for HTTP 200 OK Response
Filename: http_check_200.nse

description = [[
Checks if a web server returns HTTP 200 OK.
]]

author = "YourName"
categories = {"safe", "custom"}

portrule = function(host, port)
    return port.state == "open" and port.service == "http"
end

action = function(host, port)
    local socket = nmap.new_socket()
    socket:connect(host.ip, port.number)
    socket:send("HEAD / HTTP/1.0\r\n\r\n")
    local status, response = socket:receive()
    socket:close()

    if response and response:match("200 OK") then
        return "Web server returned HTTP 200 OK"
    else
        return "Web server did not return HTTP 200 OK"
    end
end


## Script 2: Detect Open FTP Servers
Filename: ftp_open_detect.nse

description = [[
Detects open FTP servers and checks for anonymous login.
]]

author = "YourName"
categories = {"discovery", "safe"}

portrule = function(host, port)
    return port.state == "open" and port.service == "ftp"
end

action = function(host, port)
    local socket = nmap.new_socket()
    socket:connect(host.ip, port.number)
    socket:send("USER anonymous\r\nPASS guest@\r\n")
    local status, response = socket:receive()
    socket:close()

    if response and response:match("230") then
        return "Anonymous FTP login allowed"
    else
        return "FTP server detected, but anonymous login not allowed"
    end
end
