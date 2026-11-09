variable "region" {
  type    = string
  default = "us-east-1"
}

variable "owner" { type = string }

variable "reserved_concurrency" {
  type        = number
  default     = -1
  description = "Reserved concurrency to cap blast radius. -1 = unreserved (required on new accounts: AWS keeps 10 unreserved and new accounts start at 10)."
}
