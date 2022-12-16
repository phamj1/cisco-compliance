terraform {
  required_providers {
    jupiterone = {
      source = "JupiterOne/jupiterone"
      version = "0.2.0"
    }
  }
}

provider "jupiterone" {
  # Configuration options
  api_key = var.jupiterone_api_key
  account_id = var.jupiterone_account
}