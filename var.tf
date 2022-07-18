

variable "region" {
  default = "us-east-1"
}
variable "role_name" {
  default = "p4-lambda-poc-test"
}
variable "managed_policies" {
  default = ["arn:aws:iam::aws:policy/AmazonS3FullAccess",
    "arn:aws:iam::aws:policy/CloudWatchFullAccess",
    "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
    "arn:aws:iam::aws:policy/AmazonS3OutpostsFullAccess",
    "arn:aws:iam::aws:policy/AWSLambda_FullAccess",
    "arn:aws:iam::aws:policy/service-role/AmazonS3ObjectLambdaExecutionRolePolicy",
    "arn:aws:iam::aws:policy/AmazonS3OutpostsReadOnlyAccess",
  ]
}

variable "allowed_region" {
  default = "us-east-1"
}  
    