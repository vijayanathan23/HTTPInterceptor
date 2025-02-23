package UI

import (
	"log"
	"net/http"
	"os"
)

// WebInterfaceHandler serves a simple interface
func WebInterfaceHandler(w http.ResponseWriter, r *http.Request) {
	html, err := os.ReadFile("./ui/DisplayIntercepts.html")
	if err != nil {
		log.Printf("Failed to load HTML file: %v", err)
		http.Error(w, "Failed to load interface", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}
