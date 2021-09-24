//  Example usage:
//	go run passwordhasher.go
//	go run passwordhasher.go --port=80


package main

import (
	"time" ; "fmt"; "log"; "io"
	"io/ioutil"
	"flag"
	"net/http"; "net/url"
	"context"; "sync"
    "strconv"
	"encoding/json"
	"crypto/sha512"; "encoding/base64"
	
)



// Global Variables


var passwordDataMutex sync.RWMutex
type passwordDataElement struct {
	requestedTime time.Time
	passwordHashbase64 string
}
var passwordData []passwordDataElement

var serverStats struct {
	sync.RWMutex
	newHashNumRequests int
	newHashMicroSecs int64
} = struct {
	sync.RWMutex
	newHashNumRequests int
	newHashMicroSecs int64
}{
	newHashNumRequests: 0,
	newHashMicroSecs: 0,
}



// Functions



func parseURLParams(req *http.Request, bodyData *[]byte) (url.Values, error) {
		//fmt.Println("    len(req.URL.RawQuery) =", len(req.URL.RawQuery))
		//fmt.Println("    len(*bodyData) =", len(*bodyData))

	// Note:
	//	In the case of browsers  or "curl http://...<ADDRESS>...?paramName=paramValue",
	//		the request will be a "GET" request and the parameters will be stored in the URL.RawQuery field
	//	In the case of "curl --data paramName=paramValue http://...<ADDRESS>...",
	//		the request will be a "POST" request and the parameters will be stored in the request body
	var possibleURLParams string
	if (len(req.URL.RawQuery) > 0) {
		possibleURLParams = req.URL.RawQuery
	} else if (len(*bodyData) > 0) {
		possibleURLParams = string(*bodyData)
	}

	queryVals, err := url.ParseQuery(possibleURLParams)
	if err != nil {
		log.Print(err)
		return nil, err
	}
	return queryVals, nil
}

// Handle requests that weren't sent to one of the pre-defined end points
func handleGeneralRequest(w http.ResponseWriter, req *http.Request) {
	http.NotFound(w, req)
	fmt.Fprint(w,
		"The only endpoints available on this server are:\n" +
		"    .../hash - used to encode the provided password\n" +
		"    .../hash/<passwordID> - this will retrieve the encoded password data if it is available\n" +
		"    .../stats - this will return a few server statistics\n" +
		"    .../shutdown - gracefully shut down the server.  The server will immediately stop accepting new connections and will wait for all active connections for graceful shutdown\n")
}

// Store and base64encode hash of a new password if provided
func handleHashRequest_rootOnly(w http.ResponseWriter, req *http.Request) {

    startTime := time.Now()
	

	// Do the one time read of req.Body data 
	bodyData, err := ioutil.ReadAll(req.Body)
	if err != nil {
		log.Print(err)
		return
	}
	

	queryVals, err := parseURLParams(req, &bodyData)
	if err != nil {
		log.Print(err)
		return
	}

	paramVals, paramExists := queryVals["password"]
	if (paramExists) {
		pwPlainText := paramVals[0]
		hashVal := sha512.Sum512([]byte(pwPlainText))

		passwordDataMutex.Lock()
		passwordData = append(passwordData, passwordDataElement{
			requestedTime: startTime,
			passwordHashbase64: base64.StdEncoding.EncodeToString(hashVal[:]),
		})
		passID := len(passwordData)
		passwordDataMutex.Unlock()
		fmt.Fprint(w, passID, "\n")
	} else {
		fmt.Fprint(w, "Error: no password given\n")
	}

  //Update process requests and time taken for processing
	serverStats.Lock()
	serverStats.newHashNumRequests++
	serverStats.newHashMicroSecs += time.Now().Sub(startTime).Microseconds()
	serverStats.Unlock()
}

// Returns a request handler function that will return the encoded password corresponding with the ID provided (if available)

func makeFunc_handleHashRequest(w http.ResponseWriter, req *http.Request ) {


    switch req.Method {
	case "GET":
		// Parse the requested ID
		reqID := req.URL.Path[len("/hash/"):]
		id, err := strconv.ParseUint(reqID, 0, 64)
		if err != nil {
			 http.Error(w, fmt.Sprintf("Expected request id to be an integer, but got '%s'\n", reqID), http.StatusBadRequest)
			return
		}

        var passwordHashbase64 string
		passwordHashbase64Available := false
		passwordDataMutex.RLock()
		if (1 <= id) && ( int64(id)  <= int64(len(passwordData))) && (time.Since(passwordData[id-1].requestedTime).Seconds() >= 5) {
			passwordHashbase64Available = true
			passwordHashbase64 = passwordData[id-1].passwordHashbase64
		}
		passwordDataMutex.RUnlock()

		if passwordHashbase64Available {
			io.WriteString(w, passwordHashbase64 + "\n")
			return
		} else {
			http.NotFound(w, req)  // no pattern matched (no corresponding hash ID available yet) - send 404 response
			return
		}

	}
}



// Returns some server statistics
func handleStatsRequest(w http.ResponseWriter, req *http.Request) {
         

	   serverStats.RLock()
	    stats := struct {
		  Total int  "total"  // Need to give this a field lable to get "total" to have a lower case name in the JSON output
		  Average float32  "average"  // Similar for "average"
	    }{
	    	Total: serverStats.newHashNumRequests,
		 Average: float32(serverStats.newHashMicroSecs) /  float32(serverStats.newHashNumRequests),
	    }
	    serverStats.RUnlock()

	    encodedStats, err := json.Marshal(stats)
	    if err == nil {
		    io.WriteString(w, string(encodedStats) + "\n")
	    }
        
        if stats.Total == 0 {
          fmt.Fprint(w, "No stats yet for hashing\n")
        }

}



// Main


func main() {
	log.SetFlags(log.Ldate | log.Lmicroseconds | log.Lshortfile)


	
	// Parse command line parameters
	

	var showHelp = flag.Bool("help",
		false,
		"Show help",
	)
	var serverPort = flag.Int("port",
		80,
		"Port number for the HTTP password hasher server to use",
	)
	flag.Parse()
	if *showHelp {
		flag.PrintDefaults()
		return
	}
	if (0 > *serverPort) || (*serverPort > 65535) {
		fmt.Println("Invalid port number - must be in the range [0, 65535]")
		return
	}
	

	
	// Initialize  handlers for HTTP server and the HTTP server itself
	
	shutdownRequested := make(chan string)
	handleShutdownRequest := func(w http.ResponseWriter, req *http.Request) {
		close(shutdownRequested)
	}

	
	
	http.HandleFunc("/hash/", makeFunc_handleHashRequest)
	http.HandleFunc("/hash", handleHashRequest_rootOnly)
	http.HandleFunc("/stats", handleStatsRequest)
	http.HandleFunc("/", handleGeneralRequest)  // If this doesn't happen, the default handler just returns "404 page not found"
	http.HandleFunc("/shutdown", handleShutdownRequest)
	http.HandleFunc("/shutdown/", handleShutdownRequest)

	

	//initialize the server in the default or given port

    log.Print("Creating server on port ", *serverPort, "\n")

	server := &http.Server{Addr: fmt.Sprintf(":%d", *serverPort)}

	
	


	
	// Run HTTP server and until a shutdown request comes
	

	const serverInitError = "Initialization error"

	shutdownComplete := make(chan struct{})

	go func() {
		err := server.ListenAndServe()
		if err != nil {
			log.Printf("HTTP server message: %v", err)
			if err != http.ErrServerClosed {
				shutdownRequested <- serverInitError
				log.Println("HTTP server couldnot start")
				close(shutdownRequested)
			}
		}
		close(shutdownComplete)
		
	}()

	shutdownRequestCause := <- shutdownRequested
	if shutdownRequestCause != serverInitError {
		log.Println("Shutting down server...")
		// gracefully shutdown the server:
        // waiting indefinitely for connections to return to idle and then shut down.
        server.SetKeepAlivesEnabled(false)
        err := server.Shutdown(context.Background());
		if err != nil {
			// Error from closing listeners, or context timeout:
			log.Printf("HTTP server could not gracefully shutdown: %v", err)
		}
        log.Println("Server created and then shutdown...")
		<- shutdownComplete  // Wait for the shutdown to finish
	}


}



