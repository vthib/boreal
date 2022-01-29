/*
    This is a description of the rule
*/
rule ga: BU
{
   meta:
        author = "The Shadoks"
   strings:
    	$a = "zo"
        $b = "MEU"
   condition:
    	all of them

}
