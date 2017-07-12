from pyad import aduser
import ldap
l = ldap.initialize('ldap://localhost')
username = "raj@itm.wipro.com"
password = "Wipro@123"

l.protocol_version = ldap.VERSION3



try:
    l.protocol_version = ldap.VERSION3
    l.set_option(ldap.OPT_REFERRALS, 0)
    l.simple_bind_s(username, password)
    print 'success'
    print l
except ldap.INVALID_CREDENTIALS:
    print "Your username or password is incorrect."
    
except Exception, e:
   print e






f=open("input.csv","r")
f1=open("output.csv","w")
c=1
f1.write('"name","userPrincipalName","location","department","telephoneNumber","manager"\n')
s=file("input.csv").read()
for word in s.split():
    if(c==1):
        c=c-1
    else:
        a=l.search_s("dc=itm,dc=wipro,dc=com",ldap.SCOPE_SUBTREE,'name='+word)
        f1.write(a[0][1]['displayName'][0]+","+a[0][1]['userPrincipalName'][0]+",")
        if('physicalDeliveryOfficeName' in a[0][1]):
            f1.write(a[0][1]['physicalDeliveryOfficeName'][0]+",")
        else:
            f1.write("--------,")
        if('department' in a[0][1]):
            f1.write(a[0][1]['department'][0]+",")
        else:
            f1.write("-------,")
        if('telephoneNumber' in a[0][1]):
            f1.write(a[0][1]['telephoneNumber'][0]+",")
        else:
            f1.write("-------,");
        if('manager' in a[0][1]):
            f1.write(a[0][1]['manager'][0])
        else:
            f1.write("-------")
        f1.write("\n")
          
f1.close()
f.close()
