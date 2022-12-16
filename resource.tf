resource "jupiterone_question" "COSI_1-1" {
  title = "AWS S3 Buckets"
  description = "Return all S3 Buckets required for COSI Compliance."
  tags = ["COSI", "AWS", "S3"]

  query {
    name = "Public S3 Buckets that Allows Grant Everyone"
    query = <<EOF
find aws_s3_bucket 
  with 
    (tag.[Data Classification] != 'Cisco Public' and
    tag.DataClassification != 'Cisco Public') and
    ignorePublicAcls != true and 
    restrictPublicBuckets != true
  as bucket
that allows as grant everyone 
return 
  bucket.displayName as bucketName,
  bucket.accountId as accountId,
  bucket.tag.AccountName as accountName,
  grant.permission as permission,
  grant.granteeType as granteeType,
  grant.granteeURI as granteeURI,
  bucket._id as jOneId
EOF
    version = "v1"
  }

  query {
    name = "Public S3 Buckets that has Public Policy"
    query = <<EOF
find aws_s3_bucket 
  with
    (tag.[Data Classification] != 'Cisco Public' and
    tag.DataClassification != 'Cisco Public') and
    ignorePublicAcls != true and 
    restrictPublicBuckets != true
  as bucket
that has aws_s3_bucket_policy with public=true
return 
  bucket.displayName as bucketName, 
  bucket.accountId as accountId,
  bucket.tag.AccountName,
  bucket._id as jOneId
EOF
    version = "v1"
  }

  compliance {
    standard = "COSI Compliance Queries"
    requirements = ["1.1"]
  }

}


resource "jupiterone_question" "COSI_1-2" {
  title = "AWS Root User without MFA for COSI"
  description = "Return all root users in AWS that do not have MFA."
  tags = ["COSI", "AWS"]

  query {
    name = "AWS Root Users without MFA"
    query = "Find aws_account with _source!='system-mapper' and mfaEnabled!=true as aws return   aws.tag.AccountName as accountName, aws.accountId, aws._id as jOneId"
    version = "v1"
  }

  compliance {
    standard = "COSI Compliance Queries"
    requirements = ["1.2"]
  }

}

resource "jupiterone_question" "COSI_1-3" {
  title = "AWS IAM Users without MFA for COSI"
  description = "Return all IAM users in AWS that do not have MFA."
  tags = ["COSI", "AWS"]

  query {
    name = "AWS IAM Users without MFA"
    query = "find aws_iam_user with passwordEnabled=true and mfaEnabled!=true as aws return aws.accountId, aws.tag.AccountName, aws._id as jOneId"
    version = "v1"
  }

  compliance {
    standard = "COSI Compliance Queries"
    requirements = ["1.3"]
  }

}

resource "jupiterone_question" "COSI_1-4" {
  title = "AWS Snapshots with Public Exposure for COSI"
  description = "Return all public facing AWS snapshots."
  tags = ["COSI", "AWS"]

  query {
    name = "AWS Snapshots with Public Exposure"
    query = "find aws_ebs_snapshot with public=truereturn DisplayName, region, accountid, tag.accountname, _id as jOneId"
    version = "v1"
  }

  compliance {
    standard = "COSI Compliance Queries"
    requirements = ["1.4"]
  }

}

resource "jupiterone_question" "COSI_1-5" {
  title = "Databases with Public Exposure for COSI"
  description = "Return all public facing databases."
  tags = ["COSI", "AWS", "GCP"]

  query {
    name = "GCP Database with Public Exposure"
    query = "find (google_sql_mysql_instance|google_sql_postgres_instance|google_sql_sql_server_instance) with authorizedNetworks='0.0.0.0/0' as sql_instance return sql_instance.projectId, sql_instance.tag.AccountName, sql_instance.name, sql_instance as jOneId"
    version = "v1"
  }

  query {
    name = "AWS Internet with Public Exposure"
    query = "FIND Internet THAT ALLOWS AS rule aws_security_group AS sg THAT PROTECTS Database AS db WHERE rule.inbound=true RETURN db.displayName, db.accountId, db.tag.AccountName, db.arn, rule.fromPort,   rule.toPort, rule.portRange, db._id as jOneId"
    version = "v1"
  }

  compliance {
    standard = "COSI Compliance Queries"
    requirements = ["1.5"]
  }

}

resource "jupiterone_question" "COSI_1-6" {
  title = "Security Groups Allowing Publicly Accessible Ports for COSI"
  description = "Return all security groups that allow publicly accessible ports."
  tags = ["COSI", "AWS"]

  query {
    name = "AWS Security Groups Allowing Publicly Accessible Ports"
    query = "Find aws_security_group as fw that ALLOWS as rule * as src where rule.ingress=true and rule.ipProtocol='tcp' and rule.fromPort<=22 and rule.toPort>=22 return fw.displayName, fw.accountId,   fw.tag.AccountName, rule.ipProtocol, rule.fromPort, rule.toPort, src.displayName, src.ipAddress, src.CIDR,fw._id as jOneId"
    version = "v1"
  }

  compliance {
    standard = "COSI Compliance Queries"
    requirements = ["1.6"]
  }

}
