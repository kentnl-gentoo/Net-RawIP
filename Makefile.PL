use ExtUtils::MakeMaker;

print "Please select type of your system (digit)\n";
print "1) Linux and glibc2 (Debian >= 2.0, RedHat >= 5.0)\n";
print "2) Linux and libc (Slackware)\n";
print "3) Solaris\n";
print "4) Systems with BSD raw socket format: FreeBSD,BSDI,... *BSD\n";
print "5) Other\n-> ";
chomp($system =<STDIN>);

if($system == 1)
{
print "Good choice,ethernet related methods now implemented only on Linux\n";  
$define = '-D_GLIBC_ -D_ETH_';
$object = 'RawIP.o util.o eth.o';
}
elsif($system == 2)
{
print "Good choice,ethernet related methods now implemented only on Linux\n";
$define = '-D_ETH_';
$object = 'RawIP.o util.o eth.o';
}
elsif($system == 3){
print "Sorry,ethernet related methods now implemented only on Linux\n"; 
$define = '-D_SOLARIS_';
$object = 'RawIP.o util.o'; 
}
elsif($system == 4){
print "Sorry,ethernet related methods now implemented only on Linux\n"; 
$define = '-D_BSDRAW_';
$object = 'RawIP.o util.o'; 
}
else{
print "Sorry,ethernet related methods now implemented only on Linux\n"; 
$define = '';
$object = 'RawIP.o util.o'; 
}  

WriteMakefile(
    'NAME'	=> 'Net::RawIP',
    'VERSION_FROM' => 'RawIP.pm', 
    'LIBS'	=> ['-lpcap'],   
    'DEFINE'	=> $define,      
    'INC'	=> '',      
    'OBJECT' => $object
);
