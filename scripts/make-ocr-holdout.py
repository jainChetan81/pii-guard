#!/usr/bin/env python3
import json, random, string, html, subprocess
"""Unseen OCR set: different fonts, themes, sizes and seed than ocr-corpus. Never tune rules against it alone."""
import os, tempfile
OUT=os.path.join(os.path.dirname(os.path.abspath(__file__)),"../test/fixtures/ocr-holdout")
HTML=tempfile.mkdtemp()
random.seed(90210)
A=string.ascii_letters+string.digits
r=lambda n,a=A:"".join(random.choice(a) for _ in range(n))
fonts=["'Liberation Mono'","'Noto Sans Mono'","'Nimbus Mono PS'","'Liberation Sans'","'Nimbus Sans'","'Liberation Serif'","'URW Gothic'"]
themes=[("#0d1117","#c9d1d9"),("#ffffff","#24292f"),("#002b36","#93a1a1"),("#fdf6e3","#657b83"),("#1e1e2e","#cdd6f4"),("#f5f5f5","#555555")]
def luhn(prefix,n):
  while True:
    s=prefix+r(n-len(prefix)-1,string.digits)
    for c in "0123456789":
      d=[int(x) for x in s+c][::-1]; t=sum(x if i%2==0 else (x*2-9 if x*2>9 else x*2) for i,x in enumerate(d))
      if t%10==0: return s+c
gen={
 "anthropic_key":lambda:("ANTHROPIC_API_KEY=","sk-ant-api03-"+r(48,A+"_-")),
 "openai_key":lambda:("OPENAI_API_KEY=","sk-proj-"+r(48)),
 "github_token":lambda:("token: ","ghp_"+r(36)),
 "aws_access_key":lambda:("aws_access_key_id = ","AKIA"+r(16,string.ascii_uppercase+string.digits)),
 "openrouter_key":lambda:("OPENROUTER_KEY=","sk-or-v1-"+r(64,"0123456789abcdef")),
 "google_api_key":lambda:("maps key ","AIza"+r(35,A+"_-")),
 "slack_token":lambda:("SLACK_BOT=","xoxb-"+r(12,string.digits)+"-"+r(24)),
 "jwt":lambda:("Authorization: Bearer ","eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ"+r(40)+"."+r(43,A+"_-")),
 "connection_string":lambda:("DATABASE_URL=","postgresql://svc_"+r(4).lower()+":"+r(16)+"@pg-"+r(4).lower()+".internal.net:5432/app"),
 "email":lambda:("Email: ","arjun.menon"+r(2,string.digits)+"@fastmail.com"),
 "in_phone":lambda:("Mobile: ","+91 "+random.choice("6789")+r(4,string.digits)+" "+r(5,string.digits)),
 "pan":lambda:("PAN: ","ABCPM"+r(4,string.digits)+"K"),
 "credit_card":lambda:("Mastercard ",(lambda c:" ".join(c[i:i+4] for i in range(0,16,4)))(luhn("5555",16))),
 "upi":lambda:("Pay to ","arjun"+r(3,string.digits)+"@ybl"),
 "ifsc":lambda:("IFSC code ","ICIC0"+r(6,string.digits)),
 "us_ssn":lambda:("SSN ",f"{random.randint(100,665)}-{random.randint(10,99)}-{random.randint(1000,9999)}"),
 "ip_address":lambda:("host ",f"34.{random.randint(10,200)}.{random.randint(1,254)}.{random.randint(1,254)}"),
}
clean=[["Total revenue: 1,24,500","Orders: 342 (up 12%)","Updated 05 Nov 2026, 14:32"],["def handler(event):","    return {'status': 200}","# v2.4.1"],["Meeting at 3:30 pm in room B-204","Bring the Q3 deck, slides 4-9"],["npm install react@18.3.1","added 3 packages in 1.2s"]]
cases={}; i=0
for rules in [random.sample(list(gen),3) for _ in range(14)]:
  i+=1; bg,fg=random.choice(themes); font=random.choice(fonts); size=random.choice([12,13,14,15,16,18,20])
  lines=[]; 
  for k in rules: p,v=gen[k](); lines.append(p+v)
  name=f"h{i:02d}.png"; cases[name]=rules
  open(f"{HTML}/{name}.html","w").write(f"<html><body style=\"margin:0;padding:18px;background:{bg};color:{fg};font:{size}px {font}\">"+"<br>".join(html.escape(l) for l in lines)+"</body></html>")
for j,lines in enumerate(clean):
  name=f"c{j+1:02d}.png"; cases[name]=[]; bg,fg=random.choice(themes)
  open(f"{HTML}/{name}.html","w").write(f"<html><body style=\"margin:0;padding:18px;background:{bg};color:{fg};font:15px {random.choice(fonts)}\">"+"<br>".join(html.escape(l) for l in lines)+"</body></html>")
for name in cases:
  w=random.choice([900,1100,1280])
  subprocess.run(["google-chrome","--headless=new","--disable-gpu","--no-sandbox","--user-data-dir=/tmp/ocr-holdout/chrome","--hide-scrollbars",f"--window-size={w},200",f"--screenshot={OUT}/{name}",f"file://{HTML}/{name}.html"],capture_output=True)
json.dump(cases,open(f"{OUT}/labels.json","w"),indent=1)
