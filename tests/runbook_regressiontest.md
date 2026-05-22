# Runbook regression test

# Prepare
Truncate users, tokens
Restart the FastAPI server
Delete cookies from browser

# Visit page
https://vps1.mcs2web.com/chessvariantnotes/


# Register
username test123
my email 1
password 12345
password abcde
password ABCDE
password wjH@g847Fi#kwj#w

wait for the email
click the link to complete registration

# Register duplicate
username test123
my email 2
username test456
my email 1
username test456
my email 2
password cb8y!fUEq7bd goes fine

Do not use the registration link but register one more time with:
username test456
my email 2
password cb8y!fUEq7bd

# Login logout
login with wrong password
login with password with trailing/leading space
login with password of other username
login with username with leading space
logout
login with username with trailing space
logout
leave page, re-visit page, still logged out
login
leave page, re-visit page, still logged in


# Change password
Click reset password while logged out
Enter non-existing email abc2o8f480fh@abcx21f.com
Enter my email 1 and click send
Use the reset password link to reset password, new password: wjH@g847Fi#Qwj#w

Log in as my email 2
Click reset password while logged in as my email 2
Enter non-existing email abc2o8f480fh@abcx21f.nl
Enter my email 2 and click send
Use the reset password link to reset password, new password: cb8y!fUEq76d

# Change username
On behalf of my email 1 try to change to test456
On behalf of my email 2 try to change to test123
Try change username while not logged in
