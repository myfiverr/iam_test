
region                      = "us-east-1"
allowed_region              = "us-east-1"
role_name                   = "User_role"
managed_policies            = ["arn:aws:iam::aws:policy/AmazonS3FullAccess",
                                "arn:aws:iam::aws:policy/CloudWatchFullAccess",
                                "arn:aws:iam::aws:policy/AWSLambda_FullAccess",
                                "arn:aws:iam::aws:policy/AmazonRDSFullAccess"]
