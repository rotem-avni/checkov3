package main

import (
	"C"
	"encoding/json"
	"log"
)

type response struct {
	Path string `json:"path"`
}

//export analyzeCode
func analyzeCode(documentPtr *C.char) *C.char {

	documentString := C.GoString(documentPtr)
	jsonDocument := response{}
	err := json.Unmarshal([]byte(documentString), &jsonDocument)
	if err != nil {
		log.Fatal(err)
	}
	mapD := map[string]int{"matches": 0, "profiler": 0}
	toReturn, _ := json.Marshal(mapD)
	return C.CString(string(toReturn))
}

func main() {
}
