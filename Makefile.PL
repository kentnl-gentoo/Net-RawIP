use ExtUtils::MakeMaker;

print "Please select type of your system (digit)\n";
print "1) Linux and glibc2 (Debian >= 2.0, RedHat >= 5.0)\n";
print "2) Linux and libc (Slackware)\n";
print "3) Solaris\n";
print "4) NetBSD,OpenBSD\n";
print "5) FreeBSD\n";
print "6) BSDI\n";
print "7) Other\n-> ";
chomp($system =<STDIN>);

if($system == 1)
{
print "The rdev function need for /proc/net/route\n"
                                              unless -e "/proc/net/route"; 
$define = '-D_LINUX_ -D_GLIBC_ -D_ETH_';
$object = 'RawIP.o util.o eth.o ifaddrlist.o';
}
elsif($system == 2)
{
print "The rdev function need for /proc/net/route\n" 
                                              unless -e "/proc/net/route";
$define = '-D_LINUX_ -D_ETH_';
$object = 'RawIP.o util.o eth.o ifaddrlist.o';
}
elsif($system == 3){
print "Sorry,ethernet related methods are not implemented on Solaris\n"; 
print "Sorry, the ifaddrlist function is not imlemented on Solaris\n";
print "Sorry, the rdev function is not imlemented on Solaris\n";
$define = '-D_SOLARIS_';
$object = 'RawIP.o util.o'; 
}
elsif($system == 4){
$define =  '-D_ETH_ -D_BPF_';
$object = 'RawIP.o util.o ifaddrlist.o rdev.o eth.o'; 
}
elsif($system == 5){
$define = '-D_BSDRAW_ -D_FreeBSD_ -D_ETH_ -D_BPF_';
$object = 'RawIP.o util.o ifaddrlist.o eth.o rdev.o';
}
elsif($system == 6){
$define = '-D_BSDRAW_ -D_BSDI_ -D_ETH_ -D_BPF_';
$object = 'RawIP.o util.o ifaddrlist.o eth.o rdev.o';
}
else{
print "Sorry,ethernet related methods are not implemented on this system\n"; 
print "Sorry, the ifaddrlist function is not imlemented on this system\n";
print "Sorry, the rdev function is not imlemented on this system\n";
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
