// SecureVault example YARA rules.
// Loaded automatically when yara-python is installed:  pip install yara-python
// Drop more .yar files into this folder to extend detection.

rule Ransomware_Shadow_Copy_Deletion
{
    meta:
        description = "Script or binary that deletes Volume Shadow Copies and disables recovery"
    strings:
        $vss1 = "vssadmin delete shadows" nocase ascii wide
        $vss2 = "shadowcopy delete" nocase ascii wide
        $bcd  = "recoveryenabled no" nocase ascii wide
        $wb   = "wbadmin delete catalog" nocase ascii wide
    condition:
        2 of them
}

rule Ransomware_Note
{
    meta:
        description = "Ransom note demanding cryptocurrency payment"
    strings:
        $a = "your files have been encrypted" nocase ascii wide
        $b = "bitcoin" nocase ascii wide
        $c = ".onion" nocase ascii wide
        $d = "decrypt" nocase ascii wide
    condition:
        $a and 2 of ($b, $c, $d)
}
