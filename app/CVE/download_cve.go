package main

import (
    "crypto/tls"
    "io"
    "net/http"
    "os"
)
func main() {
    fileUrl := "https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-recent.json.zip"

    if err := DownloadFile("nvdcve-1.0-recent.json.zip", fileUrl); err != nil {
        panic(err)
    }
}
// DownloadFile will download a url to a local file. It's efficient because it will
// write as it downloads and not load the whole file into memory.
func DownloadFile(filepath string, url string) error {
    // Get the data
    http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
    resp, err := http.Get(url)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    // Create the file
    out, err := os.Create(filepath)
    if err != nil {
        return err
    }
    defer out.Close()

    // Write the body to file
    _, err = io.Copy(out, resp.Body)
    return err
}

