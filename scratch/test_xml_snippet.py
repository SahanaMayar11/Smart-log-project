import os
import sys
import traceback

sys.path.insert(0, os.path.abspath('backend'))
import system_log_collector

xml = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <Provider Name='Microsoft-Windows-Security-Auditing'/>
        <EventID>4625</EventID>
        <Level>0</Level>
        <EventRecordID>34731</EventRecordID>
        <TimeCreated SystemTime='2026-10-20T22:10:04.1234567Z'/>
        <Execution ProcessID='752'/>
        <Channel>Security</Channel>
        <Computer>Rocky</Computer>
    </System>
    <EventData>
        <Data Name='TargetUserName'>Sahana</Data>
        <Data Name='TargetDomainName'>Rocky</Data>
        <Data Name='Status'>0xc000006d</Data>
        <Data Name='SubStatus'>0xc000006a</Data>
        <Data Name='LogonType'>2</Data>
    </EventData>
</Event>"""

raw_blocks = xml.split("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>")
block = raw_blocks[1]

# Replicate block processing
try:
    default_host = "Rocky"
    event_id = 1000
    if '<EventID' in block:
        id_part = block.split('<EventID')[1].split('</EventID>')[0]
        if '>' in id_part:
            id_val = id_part.split('>')[1].strip()
            event_id = int(id_val) if id_val.isdigit() else 1000

    provider = 'Microsoft-Windows-System'
    if "Provider Name='" in block:
        provider = block.split("Provider Name='")[1].split("'")[0]
    elif 'Provider Name="' in block:
        provider = block.split('Provider Name="')[1].split('"')[0]

    channel = 'Security'
    if '<Channel>' in block:
        channel = block.split('<Channel>')[1].split('</Channel>')[0].strip()

    record_id = 0
    if '<EventRecordID>' in block:
        rec_part = block.split('<EventRecordID>')[1].split('</EventRecordID>')[0].strip()
        record_id = int(rec_part) if rec_part.isdigit() else 0

    hostname = default_host
    if '<Computer>' in block:
        comp_part = block.split('<Computer>')[1].split('</Computer>')[0].strip()
        if comp_part:
            hostname = comp_part

    exec_pid = 4
    if "Execution ProcessID='" in block:
        p_str = block.split("Execution ProcessID='")[1].split("'")[0].strip()
        exec_pid = int(p_str) if p_str.isdigit() else 4

    data_dict = {}
    import re, html
    for m in re.finditer(r"<Data(?:\s+Name=['\"]([^'\"]*)['\"])?>([^<]*)</Data>", block, re.DOTALL):
        name, val = m.group(1), m.group(2)
        val = html.unescape(val or '').replace('&#13;&#10;', ' ').replace('&#13;', ' ').replace('&#10;', ' ').replace('&#9;', ' ')
        val = " ".join(val.replace('\r', ' ').replace('\n', ' ').split())
        if name:
            data_dict[name] = val
        elif val:
            data_dict[f"data_{len(data_dict)}"] = val

    print("data_dict:", data_dict)
    
    # Check 4625 block
    if event_id == 4625:
        user_raw = str(data_dict.get('TargetUserName', 'User')).replace('</Data', '').strip()
        domain = str(data_dict.get('TargetDomainName', hostname)).replace('</Data', '').strip()
        logon_type = str(data_dict.get('LogonType', '2')).strip()
        status_code = str(data_dict.get('Status', '0xc000006d')).strip()
        sub_status = str(data_dict.get('SubStatus', '0xc000006a')).strip()
        desc = f"Failed logon attempt detected for account {user_raw} on computer {hostname}."
        clean_msg = f"An account failed to log on. Account Name: {user_raw}, Domain: {domain}, Status: {status_code}, SubStatus: {sub_status}."
        print("Success! Created clean_msg:", clean_msg)

except Exception:
    traceback.print_exc()
