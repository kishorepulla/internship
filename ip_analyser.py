import Tkinter as tk
import csv
from Tkinter import *
import tkFont
from ScrolledText import *
#from ttk import *
from tkFileDialog import *
#import tkFont
import tkFileDialog
import ttk
import urllib,urllib2
#import Tkinter.font as tkFont
import json
import time
import tkMessageBox
import requests,warnings
from bs4 import BeautifulSoup
warnings.filterwarnings("ignore")

class Remote(object):
    kkk=1
    def value(self,resposnse,search_value):
        for x,x1 in resposnse.items():
            if search_value in x:
                return x,x1
    def ipvoid(self,ip):
        
        url = 'http://www.ipvoid.com/ip-blacklist-check/'
        values ={'ip':ip}
        response=requests.post(url,values)
        output = (response.content)
        soup = BeautifulSoup(output,"lxml")
        table = soup.find( "table", {"class":"table table-striped table-bordered"} )
        th = table.find('td', text='Blacklist Status')
        td = th.findNext('td')
        return td.text.encode('utf-8')

    def virus_total(self,ip):
        AP_key = 'ac0c359f07f0dcc57124e060fb3f3fce73acf80352abc9d2a887abe2cbf63a0e'
        params = {'apikey': AP_key, 'url':ip}
        response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=params)
        json_response = response.json()
        print json_response
        headers = {
          "Accept-Encoding": "gzip, deflate",
          "User-Agent" : "gzip,  My Python requests library example client or username"
          }
        params = {'apikey': AP_key, 'resource':ip}
        response = requests.post('https://www.virustotal.com/vtapi/v2/url/report',params=params, headers=headers)
        json_response = response.json()
        data = json_response.items()[8]
        print data[0]
        l= data[1]
        data = json_response.items()[9]
        print data[0]
        print data[1]
        k="Detection Ratio: ",l,"/",data[1]
        return k

    def ibm_xforce(self,ip):
        url = 'https://api.xforce.ibmcloud.com/ipr/128.31.0.39'
        headers = {"USER":"67062647-affa-498e-9910-a20c9188aac2","PASS":"5c60abac-edcd-4aaa-acc9-e9d320c4a407"}
        response = requests.get(url, auth=("67062647-affa-498e-9910-a20c9188aac2", "5c60abac-edcd-4aaa-acc9-e9d320c4a407"), headers=headers )
        ibm_response = response.json()
        if response.status_code != 200: 
            print('Status:', response.status_code, 'Headers:', response.headers, 'Error Response:',response.json())
            exit()

        score=self.value(ibm_response,'score')
        ibm_str = str(score)
        risk_value = ibm_str.strip("(u'score', " ).rstrip(')')
        return risk_value


    def blacklist(self,ip):
        url="https://www.abuseipdb.com/check/"+ip
        result=None
        r=requests.get(url)
        bs=BeautifulSoup(r.text)
        d=bs.find("div", {"class" : "well"})
        if(d is None):
            result= "404 not valid"
    
        else:
            p=d.find("p")
            h=d.find("h3")
            result= h.text
            if(p is not None):
                t= p.text
                t=t.encode('utf-8')
                if(t.find("See below for details.")=="See below for details."):
                    f=t.find("See below for details.")
                    t.replace('See below for details.','')
                    result=result+t[0:27]
        return result

    def dshield(self,ip):
        url="https://www.dshield.org/api/ip/"+ip
        r=requests.get(url)
        bs=BeautifulSoup(r.text,"lxml")
        q=0
        q=bs.find("attacks")
        t=bs.find("count")
        a1=q.text
        a2=t.text
        print t.text
        print q.text
        if(a2 == ""):
            a2 = "0"
        if(a1 == ""):
            a1="0"
            
        return "attacks: {} count: {}".format(a1,a2) 
      

    
    def machine3(self):
        self.f=[]
        for entry in self.check:
            func=entry.get()
            self.f.append(func)
            print "checccccccccccccccck"
        print self.f
        
        
        #global self.textPad
        t = self.textPad.get("1.0", "end-1c")
        print "**************IPADDRESS**************************"
        print t
        ip=t.encode('utf-8')
        print ip
        self.ip1 = ip.split("\n")
        print self.ip1
        
        

       
        print (type(self.ip1))

        
       
        for i in self.f:
            print i
        b=[]

        for i in self.ip1:
            count = 0
            if self.f[0]==1:
                count=count+1
                try:
                    
                    f1=self.ipvoid(i)
                    b.append(f1)
                    # print f1
                except Exception,e:
                    e="Error"
                    b.append(e)
            else:
                pass
                # e="None"
                # b.append(e)
            if self.f[1]==1:
                count=count+1

                try:
                    f2=self.virus_total(i)
                    b.append(f2)
                    # print f2
                except Exception,e:
                    e="Error"
                    b.append(e)
            else:
                pass
                # e="None"
                # b.append(e)
            if self.f[2]==1:
                count=count+1

                try:
                    f3=self.ibm_xforce(i)
                    b.append(f3)
                    # print f3
                except Exception,e:
                    # e="Error"
                    b.append(e)
            else:
                pass
                # e="None"
                # b.append(e)



            if self.f[3]==1:
                count=count+1

                try:
                    f4=self.blacklist(i)
                    b.append(f4)
                    # print f3
                except Exception,e:
                    # e="Error"
                    b.append(e)
            else:
                pass
                # e="None"
                # b.append(e)


            if self.f[4]==1:
                count=count+1

                try:
                    f5=self.dshield(i)
                    b.append(f5)
                    # print f3
                except Exception,e:
                    # e="Error"
                    b.append(e)
            else:
                pass
                # e="None"
                # b.append(e)

        print b
        self.a2=['slno','IP Address']

        if self.f[0] == 1:
            self.a2.append('ipvoid')
        if self.f[1] == 1:
            self.a2.append('virus_total')
        if self.f[2] == 1:
            self.a2.append('ibm_xforce')
        if self.f[3] == 1:
            self.a2.append('ipabuse')
        if self.f[4] == 1:
            self.a2.append('dshield')
        
        # print self.a2
        # self.a2=['slno','IP Address','ipvoid','virus_total','ibm_xforce']
        # range
        self.a1= [b[i:i+count] for i in range(0, len(b), count)]

        print self.a1
        cnt = 0
        for data in self.a1:
            data.insert(0,self.ip1[cnt])
            cnt = cnt + 1
        # print "**************fulllllllllll******************"
        # print self.a1

        self.slno=[]
        for i in range(1,(len(self.ip1)+1)):
            print i
            self.slno.append(i)
        # print self.slno


        cnt = 0
        for data in self.a1:
            data.insert(0,self.slno[cnt])
            cnt = cnt + 1
        # print "**************fulllllllllll******************"
        # print self.a1
        
    
        # create a treeview with dual scrollbars
        if(self.kkk==1):
            self.container = ttk.Frame(root)
            self.container.pack(fill='both', expand=True)
            self.kkk=0
        
        self.tree = ttk.Treeview(columns=self.a2, show="headings")
        vsb = ttk.Scrollbar(orient="vertical",
                            command=self.tree.yview)
        hsb = ttk.Scrollbar(orient="horizontal",
                            command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set,
                            xscrollcommand=hsb.set)
        self.tree.grid(column=0, row=0, sticky='nsew', in_=self.container)
        vsb.grid(column=1, row=0, sticky='ns', in_=self.container)
        hsb.grid(column=0, row=1, sticky='ew', in_=self.container)
        self.container.grid_columnconfigure(0, weight=1)
        self.container.grid_rowconfigure(0, weight=1)
        for col in self.a2:
            self.tree.heading(col, text=col.title(),
                              command=lambda c=col: sortby(self.tree, c, 0))
            # adjust the column's width to the header string
            self.tree.column(col,
                             width=tkFont.Font().measure(col.title()))
        # print "*******************PRINTING FINAL RESULT*******************************"
        # print self.a1
        # print 'dmapmdamdpmamdpamdma'
        # print self.a2
        # print "ab duiaiondonaoidoamopj aopndm"
        #
        for item in self.a1:
            self.tree.insert('', 'end', values=item)
           # print "hello i am a virus"
           # print item
            #print "hello i am Arnold"
            # adjust column's width if necessary to fit each value



            for ix, val in enumerate(item):
                col_w = tkFont.Font().measure(val)
                # print col_w
                if self.tree.column(self.a2[ix], width=None) < col_w:
                    self.tree.column(self.a2[ix], width=col_w)
        # print "*******************PRINTING FINAL RESULT*******************************"
        # print self.a1
        # print self.a2
        self.ip_result = []
        self.ip_result.append(self.a2)
        for i in self.a1:
            self.ip_result.append(i)
        return self.ip_result
        
    def save_command(self):
        name =tkFileDialog.asksaveasfile()
        # print(name)
        a3 = name.name
        fn=a3.encode('utf-8')
        # print("rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr")
        # print("path.name:", name.name)
        if name != "":
            # print(name)
            # print
            # slice off the last character from get, as an extra return is added
            # writer = csv.writer(file)
            # print("**************************************************************")
            data = self.machine3()
            # print("**********************data****************************************")
            # print data
            with open(fn, "w") as csvfile:
                create = csv.writer(csvfile)
                create.writerows(data)
            name.close()
          
    
    
    def iExit(self):
        qExit=tkMessageBox.askyesno("IP Analyser", "Do you want to exit")
        if qExit>0:
            self.root.destroy()
            return
    def delete_all(self):
        self.var1.set(0)
        self.var2.set(0)
        self.var3.set(0)
        self.textPad.delete(1.0, "end-1c")
       
        self.container.pack_forget() 



    def __init__(self, root):
        self.root=root

        self.tree = None
        self.var1 = IntVar()
        self.var2 = IntVar()
        self.var3= IntVar()
        self.var4= IntVar()
        self.var5 = IntVar()
        
        self.canvas = tk.Canvas(root, borderwidth=0, background="bisque")
        self.frame1 = Frame(root, width=180, height=40, background='bisque')
        self.frame1.pack(side=TOP, fill=X)
        self.frame = Frame(root, background='bisque')
        self.frame.pack()
        self.check=[]
        # added width=180, height=40, background='green'
       
        self.textPad = ScrolledText(root, width=50, height=40)
        self.textPad.pack(side=LEFT)
        #self.textPad.grid(row=1, column=0, sticky="E", padx=15, pady=10)
        
        self.M2 = tk.Label(self.frame1, text="Enter IP Address below:", background="bisque", font=(None, 12))
        self.M2.grid(row=2, column=0, sticky='E', padx=15, pady=10)
        C1 = Checkbutton(self.frame1, text="ipvoid", background="bisque", font=(None, 12),variable=self.var1)
        C1.grid(row=1, column=1, sticky="E", padx=15, pady=10)
        self.check.append(self.var1)
        C2 = Checkbutton(self.frame1, text="Virus Total", background="bisque", font=(None, 12),variable=self.var2)
        C2.grid(row=1, column=2, sticky="E", padx=15, pady=10)
        self.check.append(self.var2)
        C3 = Checkbutton(self.frame1, text="ibm xforce", background="bisque", font=(None, 12),variable=self.var3)
        C3.grid(row=1, column=3, sticky="E", padx=15, pady=10)
        self.check.append(self.var3)



        C4 = Checkbutton(self.frame1, text="ipabuse", background="bisque", font=(None, 12),variable=self.var4)
        C4.grid(row=1, column=4, sticky="E", padx=15, pady=10)
        self.check.append(self.var4)



        C5 = Checkbutton(self.frame1, text="dshield", background="bisque", font=(None, 12),variable=self.var5)
        C5.grid(row=1, column=5, sticky="E", padx=15, pady=10)
        self.check.append(self.var5)



        
        self.frame = tk.Frame(self.canvas, background="bisque")
       
        
       

        self.M1 = tk.Label(self.frame1, text="Select Functions:", background="bisque", font=(None, 12))
        self.M1.grid(row=1, column=0, sticky='E', padx=15, pady=10)
        #self.E = tk.Entry(self.frame1, width=50)
        #self.E.grid(row=1, column=3, sticky="E", padx=15, pady=10)
        #self.btn = tk.Button(self.frame1, text='Submit',command=self.machine)  # and on butto

        # self.btn.grid(row=0, column=4, sticky="E", padx=15, pady=10)

        self.fbtn = tk.Button(self.frame1, text='Exit', command=self.iExit)  # and on button

        self.fbtn.grid(row=1, column=11, sticky="E", padx=15, pady=10)
        
        self.fbtn = tk.Button(self.frame1, text=' Run and Save', command=self.save_command)  # and on button

        self.fbtn.grid(row=1, column=9, sticky="E", padx=15, pady=10)
        #self.fbtn = tk.Button(self.frame1, text='Refresh', command = self.delete_all)  # and on button

        #self.fbtn.grid(row=1, column=10, sticky="E", padx=15, pady=10)
        
       
        
        


if __name__ == "__main__":
    root = tk.Tk()
    root.title("IP Analyser")
    Remote(root)
    
    root.mainloop()
