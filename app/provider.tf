provider "google" {
  credentials = "${file("/Users/yishaihalpert/Documents/GKE-Cluster-75cf07630dbd.json")}"
  project     = "yishaihl32-gke"
  region      = "us-central1-c"
}
