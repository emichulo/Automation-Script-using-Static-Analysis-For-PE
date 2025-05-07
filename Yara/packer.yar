import "pe"
import "math"

rule emotet_packer {
   meta:
      description = "recent Emotet packer pdb string"
      author = "Marc Salinas (@Bondey_m)"
      reference = "330fb2954c1457149988cda98ca8401fbc076802ff44bb30894494b1c5531119"
	  reference = "d08a4dc159b17bde8887fa548b7d265108f5f117532d221adf7591fbad29b457"
	  reference = "7b5b8aaef86b1a7a8e7f28f0bda0bb7742a8523603452cf38170e5253f7a5c82"
	  reference = "e6abb24c70a205ab471028aee22c1f32690c02993b77ee0e77504eb360860776"
	  reference = "5684850a7849ab475227da91ada8ac5741e36f98780d9e3b01ae3085a8ef02fc"
	  reference = "acefdb67d5c0876412e4d079b38da1a5e67a7fcd936576c99cc712391d3a5ff5"
	  reference = "14230ba12360a172f9f242ac98121ca76e7c4450bfcb499c2af89aa3a1ef7440"
	  reference = "4fe9b38d2c32d0ee19d7be3c1a931b9448904aa72e888f40f43196e0b2207039"
	  reference = "e31028282c38cb13dd4ede7e9c8aa62d45ddae5ebaa0fe3afb3256601dbf5de7"
      date = "2017-12-12"
    strings:
		$pdb1 = "123EErrrtools.pdb"
		$pdb2=  "gGEW\\F???/.pdb"

    condition:
       $pdb1 or $pdb2
}

rule UPX_Packed {
    meta:
        description = "Detects UPX packed files"
    strings:
        $upx1 = "UPX0"
        $upx2 = "UPX1"
    condition:
        any of them
}

rule ASPack_Packed {
    meta:
        description = "Detects ASPack packed files"
    strings:
        $aspack1 = "ASPack"
    condition:
        $aspack1
}

rule FSG_Packed {
    meta:
        description = "Detects FSG packed files"
    strings:
        $fsg1 = "FSG!"
    condition:
        $fsg1
}

rule MPRESS_Packed {
    meta:
        description = "Detects MPRESS packed files"
    strings:
        $mpress1 = "MPRESS1"
        $mpress2 = "MPRESS2"
    condition:
        any of them
}

rule Packer_pkr_ce1a_generic   /*This rule identifies the pkr_ce1a packer by matching known shellcode patterns, 
                                TEA algorithm constants, and high entropy levels*/
{
    meta:
        description = "Detect pkr_ce1a packer"
        author = "Lexfo"
        date = "2024-04-25"
        reference = "https://blog.lexfo.fr/StealC_malware_analysis_part1.html"
    strings:
        $shellcode_size = { 00699AF974[4]96AACB4600 }
        $shellcode_addr = { 0094488D6A[4]F2160B6800 }
        $tea_const_delta = { B979379E }
        $tea_const_sum = { 2037EFC6 }
        $tea_sum_calc1 = { 8101E134EFC6 }
        $tea_sum_calc2 = { 8145F83F020000 }
    condition:
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3C)) == 0x00004550 and
        $shellcode_size and $shellcode_addr and
        (1 of ($tea_const_*) or 2 of ($tea_sum_calc*)) and
        math.entropy(0, filesize) > 6.5
}
