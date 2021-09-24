
Author - Anu H




HTTP Post Hash handler

Parses request, then store the hashed and encoded password and time of the request in the buffered channel.


Get Handler (/hash/[id])

Parses request to get ID of password to return
Looks up ID in the map of hashed passwords and returns the hashed password, if it exists and 5 seconds passed after the submission of hashed requests.


Stats Handler (/stats)
Provides the no of requests and average time in microseconds for the hash requests received

Shutdown handler (/shutdown)
Porvides graceful shutdown of the http server

Build and Run

The code can be built with go build. This will produce the executable passwordhaserserver. The server provides the following command line options:

Usage of ./passwordhasher:
  
  -port uint
        The port for the server to listen on (default 80)
  

 
