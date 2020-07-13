rule Zero_2_Auto_CruLoader
{
	meta:
	    author="daevlin"
	    description="Zero2Auto CruLoader"
	    reference="https://courses.zero2auto.com/"
    strings:
        $cruloader_pdb = "Cruloader_Payload.pdb" wide ascii
        $cruloader_string = "cruloader" wide ascii


    condition:
        ($cruloader_pdb  or $cruloader_string)
}
