variable config_path {
  description = "Path to base configuration directory"
  type        = string
}

variable interface_key {
  description = "Key within the configuration path to use for the interface configuration"
  type        = string
  default     = "interfaces"
}
