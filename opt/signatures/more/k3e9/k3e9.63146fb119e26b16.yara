
rule k3e9_63146fb119e26b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63146fb119e26b16"
     cluster="k3e9.63146fb119e26b16"
     cluster_size="5"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob malicious"
     md5_hashes="['3b699c926e9b218874642619f3a52714','a41ead7339413f0fc7d21bf1b278f9a4','bc1fa84acf1ea4a10c94eabb0c745e1e']"

   strings:
      $hex_string = { 0077007300280054004d00290020004f007000650072006100740069006e0067002000530079007300740065006d0000003e000d000100500072006f00640075 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
