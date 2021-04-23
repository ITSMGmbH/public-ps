#100M Testfile
$size = "100"
$in = "http://speedtest.frankfurt.linode.com/garbage.php?r=0.29286396544417626&ckSize=" + $size
$out = $env:temp +"\speedtest.bin"
$wc = New-Object System.Net.WebClient; "{0:N2} Mbit/sec" -f ((100/(Measure-Command {$wc.Downloadfile($in,$out)}).TotalSeconds)*8); del $out