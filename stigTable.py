import requests
import json
import csv


token = "PuycKGjOiD6r0kC_ajbqG4cf"
headers = {'Authorization': 'Token token='+token, 'Content-Type': 'application/json', 'Dradis-Project-Id': '2'}

rule_title = "title"
vuln_id = "V-72841"
ipAddress = "192.168.112.10"
vuln_id_severity = "medium"
group_title	 = "SRG-APP-000142-DB-000094"
rule_id	= "SV-87493r2_rule"
stig_id	= "PGS9-00-000100"
discussion = "Discussion stuff"
check_content = "Check Content Stuff"
fix_text = "Fix stuff"
mitigations = "Insert mitigations here if this is a finding."
status = "open"

cat1_open = 0
cat2_open = 0
cat3_open = 0

cat1_pass = 0
cat2_pass = 0
cat3_pass = 0 

cat1_na = 0
cat2_na = 0
cat3_na = 0

with open ('RHEL7.csv') as csv_file:
    csv_reader = csv.DictReader(csv_file)
    for row in csv_reader:
        rule_title = row['Rule Title']
        vuln_id = row['Vuln ID']
        ipAddress = row['IPAddress']
        vuln_id_severity = row["Severity"]
        group_title = row["Group Title"]
        rule_id = row["Rule ID"]
        stig_id = row['STIG ID']
        discussion = row['Discussion']
        check_content = row['Check Content']
        fix_text = row['Fix Text']
        status = row['Status']
        if status == 'Open':
            if vuln_id_severity == 'high':
                cat1_open += 1
            elif vuln_id_severity == 'medium':
                cat2_open += 1
            elif vuln_id_severity == 'low':
                cat3_open += 1
        
        elif status == 'Not A Finding':
            if vuln_id_severity == 'high':
                cat1_pass += 1
            elif vuln_id_severity == 'medium':
                cat2_pass += 1
            elif vuln_id_severity == 'low':
                cat3_pass += 1
        elif status == 'Not Applicable':
            if vuln_id_severity == 'high':
                cat1_na += 1
            elif vuln_id_severity == 'medium':
                cat2_na += 1
            elif vuln_id_severity == 'low':
                cat3_na += 1

#build table

stigTable = json.dumps({"note":{"text": "#[Title]#\r\nSTIG Table\r\n\r\n#[Table]#\r\n|_. |_. Pass |_. Fail |_. Not Applicable |\r\n|CAT I |"+str(cat1_pass)+"|"+str(cat1_open)+"|"+str(cat1_na)+"|\r\n|CAT II |"+str(cat2_pass)+"|"+str(cat2_open)+"|"+str(cat2_na)+"|\r\n|CAT III |"+str(cat3_pass)+"|"+str(cat3_open)+"|"+str(cat2_na)+"|\r\n\r\n"}})

#stigTable = json.dumps({"note":{"text": "#[Title}#\r\nSTIG Table\r\n\r\n#[Table]#\r\n|_. |_. Pass\r\n|Test|"+str(cat1_na)+"|\r\n\r\n"}})

note = requests.post("https://172.16.206.249/pro/api/nodes/20/notes", data=stigTable, headers=headers, verify=False)
print(note.status_code)
print(note.json)