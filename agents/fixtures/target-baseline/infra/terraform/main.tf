# 虛構的網路與儲存設定，含刻意的設定錯誤。只供 Checkov 靜態分析，不會實際 apply。
terraform {
  required_version = ">= 1.5"
}

provider "aws" {
  region = "ap-northeast-1"
}

resource "aws_vpc" "main" {
  cidr_block = "10.20.0.0/16"
}

# 正式與測試在同一個 VPC，測試子網段可直連正式資料庫（未分段）
resource "aws_security_group" "order_db_prod" {
  name   = "order-db-prod"
  vpc_id = aws_vpc.main.id

  ingress {
    description = "app subnets"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.20.1.0/24", "10.20.9.0/24"] # 10.20.9.0/24 是測試環境
  }
}

# 訂單匯出檔放在公開讀取的儲存空間
resource "aws_s3_bucket" "order_exports" {
  bucket = "shopsaas-demo-order-exports"
}

resource "aws_s3_bucket_acl" "order_exports" {
  bucket = aws_s3_bucket.order_exports.id
  acl    = "public-read"
}

# 快取 Redis 未啟用傳輸加密
resource "aws_elasticache_replication_group" "cache" {
  replication_group_id       = "cache-redis"
  description                = "storefront session cache"
  engine                     = "redis"
  node_type                  = "cache.t3.micro"
  num_cache_clusters         = 1
  transit_encryption_enabled = false
  at_rest_encryption_enabled = false
}
