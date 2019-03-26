
rule m3f7_0394e448c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.0394e448c0000b12"
     cluster="m3f7.0394e448c0000b12"
     cluster_size="13"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['0294d7c6dde1b329fdc23fd8dcc23523','02b5ce64c78477f9f21e9e4467d39665','f153d33531d9928ecda01fd0ddbd60fc']"

   strings:
      $hex_string = { 456c656d656e7442794964282748544d4c3527292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a5f5769646765744d616e616765722e5f52 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
