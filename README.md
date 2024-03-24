Graver
===========


# Description 
Proof of Concept script to exploit the authenticated SSTI+RCE in Grav CMS (CVE-2024-28116).
It creates a malicious RCE page on the server running the vulnerable Grav CMS.



# References:
* [https://nvd.nist.gov/vuln/detail/CVE-2024-28116](https://nvd.nist.gov/vuln/detail/CVE-2024-28116)


# Notes
Since it is an authenticated vulnerability it is needed to use valid credentials (hardcoding them on the script) of a Grav CMS editor user.


# Usage
Following is reported an usage example of the tool:

```
# python3 graver.py -t <target_url> -p <target_port>
```

Simple example with returned output:
```
# python3 graver.py -t http://www.mygrav.local -p 8000

RCE payload injected, now visit the malicious page at 'http://www.mygrav.local:8000/hacked_r79b?do='
```
![image](https://github.com/akabe1/Graver/assets/46047144/c6d478f2-573e-49ed-93bf-92a8e3dd3c5d)



# Author
graver was developed by Maurizio Siddu



# GNU License
Copyright (c) 2024 graver

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>

