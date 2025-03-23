package main

import (
	handlers "HTTPInterceptor/Handlers"
	"HTTPInterceptor/UI"
	"log"
	"net/http"
	"sync"
)

var interceptedData []map[string]string
var mu sync.Mutex

func main() {
	var wg sync.WaitGroup

	// Start proxy server
	wg.Add(1)
	go func() {
		defer wg.Done()
		proxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				log.Println("Handling in Connect")
				handlers.HandleConnect(w, r, &interceptedData, &mu)
			} else {
				log.Println("Handling in HTTP")
				handlers.HandleHTTP(w, r, &interceptedData, &mu)
			}
		})
		log.Println("Starting HTTP/HTTPS Interceptor on :8080")
		if err := http.ListenAndServe(":8080", proxy); err != nil {
			log.Fatal(err)
		}
	}()

	// Start web interface
	wg.Add(1)
	go func() {
		defer wg.Done()
		http.HandleFunc("/", UI.WebInterfaceHandler)
		http.HandleFunc("/data", func(w http.ResponseWriter, r *http.Request) {
			handlers.DataHandler(w, r, &interceptedData, &mu)
		})
		log.Println("Starting Web Interface on :8081")
		if err := http.ListenAndServe(":8081", nil); err != nil {
			log.Fatal(err)
		}
	}()

	wg.Wait()
}
