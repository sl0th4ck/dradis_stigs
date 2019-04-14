import csv
with open ('RHEL7.csv') as csv_file:
    csv_reader = csv.DictReader(csv_file)
    for row in csv_reader:
        print row['STIG ID']
